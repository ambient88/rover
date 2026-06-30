using SubnetSearch.Core.Models.Data;

namespace SubnetSearch.Core.Interfaces.Data;

/// <summary>
/// Result of a conditional (If-None-Match / If-Modified-Since) download request.
/// </summary>
public record ConditionalDownloadResult(
    bool NotModified,          // true = 304, file unchanged
    Stream? Content,           // non-null when NotModified=false
    string? NewETag,
    string? NewLastModified
);

/// <summary>
/// Абстракция для загрузки файла по URL.
/// </summary>
public interface IFileDownloader
{
    // Единственный абстрактный метод — реализуют конкретные классы.
    Task<Stream> DownloadAsync(
        string url,
        DownloadOptions options,
        IProgress<DownloadProgress>? progress = null,
        CancellationToken cancellationToken = default,
        string? partialFilePath = null);

    Task<Stream> DownloadAsync(string url, CancellationToken cancellationToken = default)
        => DownloadAsync(url, new DownloadOptions(), null, cancellationToken);

    Task<Stream> DownloadAsync(string url, IProgress<long>? progress, CancellationToken cancellationToken = default)
        => DownloadAsync(url, new DownloadOptions(),
               progress != null ? new Progress<DownloadProgress>(p => progress.Report(p.BytesDownloaded)) : null,
               cancellationToken);

    Task<Stream> DownloadAsync(string url, IProgress<DownloadProgress>? progress, CancellationToken cancellationToken = default)
        => DownloadAsync(url, new DownloadOptions(), progress, cancellationToken);

    // Sends If-None-Match / If-Modified-Since; returns 304 result or new content.
    Task<ConditionalDownloadResult> ConditionalDownloadAsync(
        string url,
        string? etag,
        string? lastModified,
        DownloadOptions options,
        IProgress<DownloadProgress>? progress = null,
        CancellationToken cancellationToken = default);
}