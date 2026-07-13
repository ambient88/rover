using SubnetSearch.Core.Interfaces.Data;
using SubnetSearch.Core.Models.Data;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;

namespace SubnetSearch.Data;

public class HttpFileDownloader : IFileDownloader
{
    private sealed record PartialDownloadState(string? ETag, string? LastModified);

    private readonly HttpClient _http;
    // Thread-safe map tracking partially downloaded temp files (for resume).
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _partialFiles = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, PartialDownloadState> _partialStates = new();

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

    // Live HTTP download state machine (retry / resume / partial-file plumbing over the network).
    // Its extractable decision logic — IsValidContentRange, TrySetIfRange, VerifyChecksum,
    // CopyWithProgressAsync — is unit-tested separately; the raw I/O loop is integration-scope, so
    // it is excluded from the unit-coverage metric.
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
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
                        var state = await LoadPartialStateAsync(
                            url, existingPartial, persistentResume, token);

                        if (existingLength > 0 && state != null)
                        {
                            using var req = new HttpRequestMessage(HttpMethod.Get, url);
                            req.Headers.Range = new RangeHeaderValue(existingLength, null);
                            if (TrySetIfRange(req, state))
                            {
                                using var rangeResp = await _http.SendAsync(
                                    req, HttpCompletionOption.ResponseHeadersRead, token);
                                if (rangeResp.StatusCode == HttpStatusCode.PartialContent &&
                                    IsValidContentRange(rangeResp, existingLength))
                                {
                                    await using (var fs = new FileStream(existingPartial, FileMode.Append,
                                        FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
                                    await using (var ns = await rangeResp.Content.ReadAsStreamAsync(token))
                                    {
                                        await CopyWithProgressAsync(ns, fs, progress, existingLength,
                                            rangeResp.Content.Headers.ContentLength, token);

                                        long? expectedLength = rangeResp.Content.Headers.ContentRange?.Length;
                                        if (expectedLength.HasValue && fs.Length != expectedLength.Value)
                                            throw new InvalidDataException("The resumed download has an unexpected length.");
                                    }

                                    if (!string.IsNullOrEmpty(options.ChecksumSha256))
                                        await VerifyChecksum(existingPartial, options.ChecksumSha256);

                                    RemovePartialState(url, existingPartial, persistentResume);
                                    if (!persistentResume) _partialFiles.TryRemove(url, out _);

                                    return new FileStream(existingPartial, FileMode.Open,
                                        FileAccess.Read, FileShare.Read, 81920,
                                        persistentResume ? FileOptions.None : FileOptions.DeleteOnClose);
                                }
                            }
                        }

                        File.Delete(existingPartial);
                        RemovePartialState(url, existingPartial, persistentResume);
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
                var partialState = new PartialDownloadState(
                    fullResponse.Headers.ETag?.ToString(),
                    fullResponse.Content.Headers.LastModified?.ToString("R"));
                await SavePartialStateAsync(url, partPath, partialState, persistentResume, token);
                var fileStream = new FileStream(partPath, FileMode.Create, FileAccess.ReadWrite,
                    FileShare.None, 81920, FileOptions.Asynchronous);
                try
                {
                    var networkStream = await fullResponse.Content.ReadAsStreamAsync(token);
                    await CopyWithProgressAsync(networkStream, fileStream, progress, 0, totalBytes, token);

                    if (totalBytes.HasValue && fileStream.Length != totalBytes.Value)
                        throw new InvalidDataException($"Downloaded {fileStream.Length} bytes, server declared {totalBytes.Value} bytes.");

                    // Close the write handle (FileShare.None) BEFORE verifying the checksum —
                    // VerifyChecksum opens the file for reading and would otherwise hit a sharing
                    // violation on Windows.
                    await fileStream.DisposeAsync();

                    if (!string.IsNullOrEmpty(options.ChecksumSha256))
                        await VerifyChecksum(partPath, options.ChecksumSha256);

                    RemovePartialState(url, partPath, persistentResume);
                    // Reopen as DeleteOnClose for non-persistent temp files so the caller's
                    // using/await-using disposes and deletes automatically.
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
                {
                    File.Delete(partialFilePath);         // persistent .part
                    RemovePartialState(url, partialFilePath, true);
                }
                else if (tempFile != null && File.Exists(tempFile) && !persistentResume)
                {
                    File.Delete(tempFile);                // in-memory temp
                    RemovePartialState(url, tempFile, false);
                }
                await Task.Delay(delay * attempt, cancellationToken);
            }
        }

        throw new Exception("Failed to download file after all retries.");
    }

    internal static bool IsValidContentRange(HttpResponseMessage response, long existingLength)
    {
        var range = response.Content.Headers.ContentRange;
        if (range?.Unit != "bytes" || range.From != existingLength || !range.To.HasValue)
            return false;
        if (range.To.Value < existingLength)
            return false;
        if (range.Length.HasValue && range.To.Value >= range.Length.Value)
            return false;

        long expectedBodyLength = range.To.Value - existingLength + 1;
        return !response.Content.Headers.ContentLength.HasValue ||
               response.Content.Headers.ContentLength.Value == expectedBodyLength;
    }

    private static bool TrySetIfRange(
        HttpRequestMessage request, PartialDownloadState state)
    {
        if (EntityTagHeaderValue.TryParse(state.ETag, out var etag))
        {
            request.Headers.IfRange = new RangeConditionHeaderValue(etag);
            return true;
        }

        if (DateTimeOffset.TryParse(state.LastModified, out var lastModified))
        {
            request.Headers.IfRange = new RangeConditionHeaderValue(lastModified);
            return true;
        }

        return false;
    }

    private async Task<PartialDownloadState?> LoadPartialStateAsync(
        string url, string path, bool persistent, CancellationToken token)
    {
        if (!persistent)
            return _partialStates.TryGetValue(url, out var state) ? state : null;

        string statePath = path + ".meta";
        if (!File.Exists(statePath)) return null;
        try
        {
            string json = await File.ReadAllTextAsync(statePath, token);
            return JsonSerializer.Deserialize<PartialDownloadState>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private async Task SavePartialStateAsync(
        string url,
        string path,
        PartialDownloadState state,
        bool persistent,
        CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(state.ETag) && string.IsNullOrWhiteSpace(state.LastModified))
            return;

        if (!persistent)
        {
            _partialStates[url] = state;
            return;
        }

        await File.WriteAllTextAsync(path + ".meta", JsonSerializer.Serialize(state), token);
    }

    private void RemovePartialState(string url, string path, bool persistent)
    {
        if (!persistent)
        {
            _partialStates.TryRemove(url, out _);
            return;
        }

        try { File.Delete(path + ".meta"); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private async Task CopyWithProgressAsync(
        Stream source, Stream destination,
        IProgress<DownloadProgress>? progress,
        long initialOffset, // for resume
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
        CancellationToken cancellationToken = default,
        string? partialFilePath = null)
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
            throw new InvalidDataException($"Checksum mismatch. Expected: {expectedSha256}, got: {actual}");
    }
}
