namespace SubnetSearch.Core.Models.Classification;

public record IpPrefix(
    string  Prefix,
    string? CountryCode,
    string? Description,
    // Host count of the prefix. A /1 covers 2^31 and a /0 covers 2^32 addresses,
    // IPv4 prefix sizes can exceed a signed 32-bit integer.
    long    IpCount
);
