namespace SubnetSearch.Core.Models.Data;

public class DownloadOptions
{
    /// <summary>Maximum number of retry attempts on error.</summary>
    public int MaxRetries { get; init; } = 3;

    /// <summary>Base delay between retries (ms), multiplied by the attempt number.</summary>
    public int RetryDelayMilliseconds { get; init; } = 2000;

    /// <summary>Timeout for each HTTP attempt (seconds).</summary>
    public int TimeoutSeconds { get; init; } = 600;

    /// <summary>
    /// Directory that holds partially downloaded files (.part) between runs.
    /// If null, the system temp directory is used (resume does not survive a restart).
    /// </summary>
    public string? PartialDownloadsDir { get; init; }

    /// <summary>Whether to resume a partially downloaded file (Range request).</summary>
    public bool UseResume { get; init; } = true;

    /// <summary>Proxy server (a string like http://host:port).</summary>
    public string? Proxy { get; init; }

    /// <summary>Expected SHA256 string (hex) used to verify after download.</summary>
    public string? ChecksumSha256 { get; init; }

    // MD5 could be added, but SHA256 is enough for now.
}