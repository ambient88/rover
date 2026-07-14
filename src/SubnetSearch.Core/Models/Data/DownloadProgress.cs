namespace SubnetSearch.Core.Models.Data;

public class DownloadProgress
{
    /// <summary>Number of bytes downloaded so far.</summary>
    public long BytesDownloaded { get; init; }
    
    /// <summary>Total file size in bytes (when known).</summary>
    public long? TotalBytes { get; init; }
}