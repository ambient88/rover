namespace SubnetSearch.Data;

public record FileMetadata(
    DateTimeOffset LastChecked,
    string? ETag         = null,
    string? LastModified = null
);
