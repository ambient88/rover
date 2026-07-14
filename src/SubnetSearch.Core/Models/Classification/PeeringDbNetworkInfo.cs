namespace SubnetSearch.Core.Models.Classification;

public record PeeringDbNetworkInfo(
    string? Website,
    string? InfoType,
    int?    IxCount = null,   // number of traffic exchange points (peerings)
    int?    NetId   = null    // internal PeeringDB ID for follow-up requests
);
