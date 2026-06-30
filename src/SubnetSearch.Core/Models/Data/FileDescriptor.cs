namespace SubnetSearch.Core.Models.Data;

public record FileDescriptor(
    string Url,
    string FileName,
    long MinSize = 1_000_000,
    TimeSpan? MaxAge = null  // null = download once, never re-check
);