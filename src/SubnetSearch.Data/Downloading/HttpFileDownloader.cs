using SubnetSearch.Core.Interfaces.Data;
using SubnetSearch.Core.Models.Data;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace SubnetSearch.Data;

public class HttpFileDownloader : IFileDownloader
{
    private readonly HttpClient _http;
    // Потокобезопасный словарь для отслеживания частично загруженных временных файлов (для возобновления)
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _partialFiles = new();

    public HttpFileDownloader(HttpClient httpClient)
    {
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    }

    public async Task<Stream> DownloadAsync(string url, CancellationToken cancellationToken = default)
        => await DownloadAsync(url, new DownloadOptions(), null, cancellationToken);

    public async Task<Stream> DownloadAsync(string url, IProgress<long>? progress, CancellationToken cancellationToken = default)
        => await DownloadAsync(url, new DownloadOptions(), progress != null ? new Progress<DownloadProgress>(p => progress.Report(p.BytesDownloaded)) : null, cancellationToken);

    public async Task<Stream> DownloadAsync(string url, IProgress<DownloadProgress>? progress, CancellationToken cancellationToken = default)
        => await DownloadAsync(url, new DownloadOptions(), progress, cancellationToken);

    public async Task<Stream> DownloadAsync(
        string url,
        DownloadOptions options,
        IProgress<DownloadProgress>? progress = null,
        CancellationToken cancellationToken = default,
        string? partialFilePath = null)
    {
        int retries = options.MaxRetries;
        int delay   = options.RetryDelayMilliseconds;

        // Cross-run resume: use a persistent .part file in the data directory when available.
        // Falls back to in-memory dict (temp files, lost on restart).
        bool persistentResume = partialFilePath != null;
        string? tempFile = persistentResume ? partialFilePath : null;

        for (int attempt = 1; attempt <= retries + 1; attempt++)
        {
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(options.TimeoutSeconds));
            using var linkedCts  = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
            var token = linkedCts.Token;

            try
            {
                // Resume: check for an existing partial file.
                if (options.UseResume)
                {
                    string? existingPartial = persistentResume
                        ? (File.Exists(tempFile) ? tempFile : null)
                        : (_partialFiles.TryGetValue(url, out var p) && File.Exists(p) ? p : null);

                    if (existingPartial != null)
                    {
                        long existingLength = new FileInfo(existingPartial).Length;
                        using var req = new HttpRequestMessage(HttpMethod.Get, url);
                        req.Headers.Range = new RangeHeaderValue(existingLength, null);
                        var rangeResp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, token);
                        if (rangeResp.StatusCode == HttpStatusCode.PartialContent)
                        {
                            await using var fs = new FileStream(existingPartial, FileMode.Append,
                                FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous);
                            var ns = await rangeResp.Content.ReadAsStreamAsync(token);
                            await CopyWithProgressAsync(ns, fs, progress, existingLength,
                                rangeResp.Content.Headers.ContentLength, token);
                            if (!string.IsNullOrEmpty(options.ChecksumSha256))
                                await VerifyChecksum(existingPartial, options.ChecksumSha256);

                            if (!persistentResume) _partialFiles.TryRemove(url, out _);

                            var finalStream = new FileStream(existingPartial, FileMode.Open,
                                FileAccess.Read, FileShare.Read, 81920,
                                persistentResume ? FileOptions.None : FileOptions.DeleteOnClose);
                            return finalStream;
                        }
                        // Server doesn't support Range — start fresh.
                        File.Delete(existingPartial);
                        if (!persistentResume) _partialFiles.TryRemove(url, out _);
                        tempFile = persistentResume ? partialFilePath : null;
                    }
                }

                // Fresh download.
                using var fullResponse = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, token);
                fullResponse.EnsureSuccessStatusCode();

                long? totalBytes = fullResponse.Content.Headers.ContentLength;

                // Use plain Asynchronous (no DeleteOnClose) so the handle can be closed in
                // the catch block without deleting the file — required for cross-retry resume
                // on both persistent and non-persistent paths (Bug: FileShare.None conflict).
                string partPath = persistentResume ? partialFilePath! : Path.GetTempFileName();
                var fileStream = new FileStream(partPath, FileMode.Create, FileAccess.ReadWrite,
                    FileShare.None, 81920, FileOptions.Asynchronous);
                try
                {
                    var networkStream = await fullResponse.Content.ReadAsStreamAsync(token);
                    await CopyWithProgressAsync(networkStream, fileStream, progress, 0, totalBytes, token);

                    if (totalBytes.HasValue && fileStream.Length != totalBytes.Value)
                        throw new InvalidDataException($"Загружено {fileStream.Length} байт, сервер заявлял {totalBytes.Value} байт.");

                    if (!string.IsNullOrEmpty(options.ChecksumSha256))
                        await VerifyChecksum(partPath, options.ChecksumSha256);

                    // Reopen as DeleteOnClose for non-persistent temp files so the caller's
                    // using/await-using disposes and deletes automatically.
                    await fileStream.DisposeAsync();
                    return persistentResume
                        ? new FileStream(partPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.None)
                        : new FileStream(partPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.DeleteOnClose);
                }
                catch
                {
                    // Close the stream before recording the partial path so the next retry
                    // (or next run) can open the file without FileShare.None conflict.
                    await fileStream.DisposeAsync();
                    if (!persistentResume)
                    {
                        _partialFiles[url] = partPath;
                        tempFile = partPath;  // ensure InvalidDataException cleanup can find it
                    }
                    throw;
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                if (attempt > retries) throw;
                await Task.Delay(delay * attempt, cancellationToken);
            }
            catch (HttpRequestException) when (attempt <= retries)
            {
                await Task.Delay(delay * attempt, cancellationToken);
            }
            catch (InvalidDataException) when (attempt <= retries)
            {
                // Delete corrupt partial data so the next attempt starts fresh.
                if (partialFilePath != null && File.Exists(partialFilePath))
                    File.Delete(partialFilePath);         // persistent .part
                else if (tempFile != null && File.Exists(tempFile) && !persistentResume)
                    File.Delete(tempFile);                // in-memory temp
                await Task.Delay(delay * attempt, cancellationToken);
            }
        }

        throw new Exception("Failed to download file after all retries.");
    }

    private async Task CopyWithProgressAsync(
        Stream source, Stream destination,
        IProgress<DownloadProgress>? progress,
        long initialOffset, // для возобновления
        long? totalBytes,
        CancellationToken token)
    {
        byte[] buffer = new byte[81920];
        int bytesRead;
        long totalRead = initialOffset;

        while ((bytesRead = await source.ReadAsync(buffer, 0, buffer.Length, token)) > 0)
        {
            await destination.WriteAsync(buffer, 0, bytesRead, token);
            totalRead += bytesRead;
            progress?.Report(new DownloadProgress
            {
                BytesDownloaded = totalRead,
                TotalBytes = totalBytes.HasValue ? initialOffset + totalBytes : null
            });
        }
    }

    public async Task<ConditionalDownloadResult> ConditionalDownloadAsync(
        string url,
        string? etag,
        string? lastModified,
        DownloadOptions options,
        IProgress<DownloadProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (!string.IsNullOrEmpty(etag))
            request.Headers.TryAddWithoutValidation("If-None-Match", etag);
        if (!string.IsNullOrEmpty(lastModified))
            request.Headers.TryAddWithoutValidation("If-Modified-Since", lastModified);

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(options.TimeoutSeconds));
        using var linked    = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token);

        if (response.StatusCode == HttpStatusCode.NotModified)
            return new ConditionalDownloadResult(true, null, null, null);

        response.EnsureSuccessStatusCode();

        string? newETag         = response.Headers.ETag?.ToString();
        string? newLastModified = response.Content.Headers.LastModified?.ToString("R");
        long? totalBytes        = response.Content.Headers.ContentLength;

        var tempFile   = Path.GetTempFileName();
        var fileStream = new FileStream(tempFile, FileMode.Create, FileAccess.ReadWrite,
                                        FileShare.None, 81920, FileOptions.DeleteOnClose);
        try
        {
            var networkStream = await response.Content.ReadAsStreamAsync(linked.Token);
            await CopyWithProgressAsync(networkStream, fileStream, progress, 0, totalBytes, linked.Token);
            fileStream.Position = 0;
            return new ConditionalDownloadResult(false, fileStream, newETag, newLastModified);
        }
        catch
        {
            await fileStream.DisposeAsync();
            throw;
        }
    }

    private async Task VerifyChecksum(string filePath, string expectedSha256)
    {
        using var sha = SHA256.Create();
        await using var stream = File.OpenRead(filePath);
        var hash = await sha.ComputeHashAsync(stream);
        string actual = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        if (!string.Equals(actual, expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"Контрольная сумма не совпадает. Ожидалось: {expectedSha256}, получено: {actual}");
    }
}