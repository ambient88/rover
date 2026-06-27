using SubnetSearch.Core.Interfaces.Data;
using SubnetSearch.Core.Models.Data;
using SubnetSearch.Data;

namespace SubnetSearch.Data;

public class DownloadManager
{
    private readonly IFileDownloader _downloader;
    private readonly IFileStorage _storage;
    private readonly IReadOnlyList<FileDescriptor> _files;
    private readonly FileMetadataStore _metaStore;

    public DownloadManager(
        IFileDownloader downloader,
        IFileStorage storage,
        IReadOnlyList<FileDescriptor> files,
        FileMetadataStore metaStore)
    {
        _downloader = downloader ?? throw new ArgumentNullException(nameof(downloader));
        _storage    = storage    ?? throw new ArgumentNullException(nameof(storage));
        _files      = files      ?? throw new ArgumentNullException(nameof(files));
        _metaStore  = metaStore  ?? throw new ArgumentNullException(nameof(metaStore));
    }

    /// <summary>
    /// Downloads all files in parallel with per-file progress reporting.
    /// progressFactory is called only for files that are actually downloaded (not Skipped/NotModified).
    /// </summary>
    public async Task<IReadOnlyList<FileDownloadResult>> DownloadAllDetailedAsync(
        DownloadOptions options,
        Func<FileDescriptor, IProgress<DownloadProgress>?>? progressFactory = null,
        bool force = false,
        int maxDegreeOfParallelism = 2,
        CancellationToken cancellationToken = default)
    {
        using var semaphore = new SemaphoreSlim(maxDegreeOfParallelism);

        var tasks = _files.Select(async file =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                bool fileValid = _storage.IsFileValid(file.FileName, file.MinSize);

                // 1. File missing or corrupted → download unconditionally.
                if (!fileValid)
                    return await DownloadAndSaveAsync(file, options, progressFactory, cancellationToken);

                // 2. Force re-download requested.
                if (force)
                    return await DownloadAndSaveAsync(file, options, progressFactory, cancellationToken);

                // 3. No MaxAge configured → never re-check (download-once semantics).
                if (file.MaxAge == null)
                    return new FileDownloadResult(file.FileName, true, Skipped: true);

                // 4. TTL not yet expired → skip.
                if (!_metaStore.IsStale(file.FileName, file.MaxAge.Value))
                    return new FileDownloadResult(file.FileName, true, Skipped: true);

                // 5. TTL expired — conditional check or resume interrupted update.
                var meta     = _metaStore.Load(file.FileName);
                string? partPath = options.PartialDownloadsDir != null
                    ? Path.Combine(options.PartialDownloadsDir, file.FileName + ".part")
                    : null;

                if (partPath != null && File.Exists(partPath))
                {
                    // Previous update download was interrupted — resume it directly.
                    return await DownloadAndSaveAsync(file, options, progressFactory, cancellationToken);
                }

                var progress = progressFactory?.Invoke(file);
                var result   = await _downloader.ConditionalDownloadAsync(
                    file.Url, meta?.ETag, meta?.LastModified, options, progress, cancellationToken);

                if (result.NotModified)
                {
                    _metaStore.Save(file.FileName, new FileMetadata(
                        DateTimeOffset.UtcNow, meta?.ETag, meta?.LastModified));
                    return new FileDownloadResult(file.FileName, true, NotModified: true);
                }

                // 6. Server returned 200 — content already downloaded by ConditionalDownloadAsync.
                // Save it directly; do NOT call DownloadAndSaveAsync (that would re-download).
                await using (result.Content)
                    await _storage.SaveAsync(file.FileName, result.Content!, cancellationToken);

                if (!_storage.IsFileValid(file.FileName, file.MinSize))
                    return new FileDownloadResult(file.FileName, false, "File is corrupted after download.");

                _metaStore.Save(file.FileName, new FileMetadata(
                    DateTimeOffset.UtcNow, result.NewETag, result.NewLastModified));
                return new FileDownloadResult(file.FileName, true);
            }
            catch (Exception ex)
            {
                // Remove the .part file on any failure so the next run starts a fresh download
                // rather than resuming a potentially corrupt partial file.
                var partPath = options.PartialDownloadsDir != null
                    ? Path.Combine(options.PartialDownloadsDir, file.FileName + ".part")
                    : null;
                if (partPath != null && File.Exists(partPath))
                    try { File.Delete(partPath); } catch { /* best-effort cleanup */ }

                bool stillValid = false;
                try { stillValid = _storage.IsFileValid(file.FileName, file.MinSize); } catch { }

                if (stillValid)
                    return new FileDownloadResult(file.FileName, true, ex.Message, Stale: true);

                return new FileDownloadResult(file.FileName, false, ex.Message);
            }
            finally
            {
                semaphore.Release();
            }
        }).ToList();

        return await Task.WhenAll(tasks);
    }

    private async Task<FileDownloadResult> DownloadAndSaveAsync(
        FileDescriptor file,
        DownloadOptions options,
        Func<FileDescriptor, IProgress<DownloadProgress>?>? progressFactory,
        CancellationToken ct)
    {
        var progress = progressFactory?.Invoke(file);

        // Use a persistent .part file so interrupted downloads resume across restarts.
        string? partPath = options.PartialDownloadsDir != null
            ? Path.Combine(options.PartialDownloadsDir, file.FileName + ".part")
            : null;

        await using var stream = await _downloader.DownloadAsync(
            file.Url, options, progress, ct, partPath);
        await _storage.SaveAsync(file.FileName, stream, ct);

        // Delete .part file on successful save.
        if (partPath != null && File.Exists(partPath))
            File.Delete(partPath);

        if (!_storage.IsFileValid(file.FileName, file.MinSize))
            return new FileDownloadResult(file.FileName, false, "File is corrupted after download.");

        _metaStore.Save(file.FileName, new FileMetadata(DateTimeOffset.UtcNow));
        return new FileDownloadResult(file.FileName, true);
    }

    /// <summary>
    /// Downloads all files in parallel and returns only the successfully downloaded file names.
    /// </summary>
    public async Task<IReadOnlyList<string>> DownloadAllAsync(
        DownloadOptions options,
        bool force = false,
        int maxDegreeOfParallelism = 2,
        CancellationToken cancellationToken = default)
    {
        var detailed = await DownloadAllDetailedAsync(options, null, force, maxDegreeOfParallelism, cancellationToken);
        return detailed
            .Where(r => r.Success)
            .Select(r => r.FileName)
            .ToList();
    }

    /// <summary>
    /// Downloads a single file with optional byte-level progress reporting.
    /// </summary>
    public async Task<bool> DownloadSingleFileAsync(
        FileDescriptor file,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        // File already valid — return immediately without downloading.
        if (_storage.IsFileValid(file.FileName, file.MinSize))
            return true;

        await using var stream = await _downloader.DownloadAsync(file.Url, progress, cancellationToken);
        await _storage.SaveAsync(file.FileName, stream, cancellationToken);

        // Verify integrity after save.
        if (!_storage.IsFileValid(file.FileName, file.MinSize))
            throw new InvalidDataException($"File corrupted after download.");

        return true;
    }
}