namespace SubnetSearch.Core.Models.Network;

public record ProviderRecommendation(
    uint    Asn,
    string  Organization,
    string? Country,
    string? Website,
    string? PricingUrl,
    string? AnchorIp,
    double? LatencyMs,
    double? PacketLoss,
    int?    PeeringCount,
    int     PrefixCount,
    double  Score,
    double? AbuserScore,
    double? RpkiScore,
    bool    InSpamhausDrop,
    IReadOnlyList<string>? IxLocations,
    ScoreBreakdown?        Breakdown,
    long    TotalIpCount    = 0,
    bool    HasIPv6         = false,
    int     IPv6PrefixCount = 0,
    int     UpstreamCount   = 0,
    bool    InRoute         = false,
    int     CoverageCount   = 0,
    int     TotalListIps    = 0
);
