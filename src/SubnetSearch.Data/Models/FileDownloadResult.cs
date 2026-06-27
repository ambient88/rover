namespace SubnetSearch.Data;

public record FileDownloadResult(
    string FileName,
    bool Success,
    string? ErrorMessage = null,
    bool Skipped = false,
    bool NotModified = false,  // 304: TTL expired but server confirmed unchanged
    bool Stale = false         // update failed, but existing local copy was kept
);