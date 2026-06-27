namespace SubnetSearch.Core.Models.Classification;

public record ProviderScanResult(
    uint    Asn,
    string? AsnHandle,        // напр. "SENKO-AS"
    string? Organization,     // напр. "Senko Digital Ltd"
    string? Website,
    string? InfoType,
    string? CountryCode,
    int?    PeeringCount,
    IReadOnlyList<string>?        IxLocations,
    IReadOnlyList<IpPrefix>       Prefixes,
    IReadOnlyList<ProviderUpstream> Upstreams,
    int     TotalIpCount,
    // Если поиск по имени вернул несколько кандидатов
    IReadOnlyList<(uint Asn, string? Name, string? Description)>? OtherCandidates = null
);
