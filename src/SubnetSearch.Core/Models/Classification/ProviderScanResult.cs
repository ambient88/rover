namespace SubnetSearch.Core.Models.Classification;

public record ProviderScanResult(
    uint    Asn,
    string? AsnHandle,        // e.g. "SENKO-AS"
    string? Organization,     // e.g. "Senko Digital Ltd"
    string? Website,
    string? InfoType,
    string? CountryCode,
    int?    PeeringCount,
    IReadOnlyList<string>?        IxLocations,
    IReadOnlyList<IpPrefix>       Prefixes,
    IReadOnlyList<ProviderUpstream> Upstreams,
    // Unique address count across overlapping prefixes.
    long    TotalIpCount,
    // Set when a name search returned several candidates
    IReadOnlyList<(uint Asn, string? Name, string? Description)>? OtherCandidates = null
);
