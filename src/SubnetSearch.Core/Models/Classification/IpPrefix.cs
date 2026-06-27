namespace SubnetSearch.Core.Models.Classification;

public record IpPrefix(
    string  Prefix,
    string? CountryCode,
    string? Description,
    int     IpCount
);
