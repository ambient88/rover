namespace SubnetSearch.Core.Models.Classification;

public record ProviderUpstream(
    uint    Asn,
    string? Name,
    string? Description,
    string? CountryCode
);
