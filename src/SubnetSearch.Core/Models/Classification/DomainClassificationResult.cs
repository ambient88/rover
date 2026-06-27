namespace SubnetSearch.Core.Models.Classification;

public record DomainClassificationResult(
    string Domain,
    IReadOnlyList<ClassificationResult> IpResults,
    string? DomainRegistrar,
    string? DomainHostingProvider,
    IReadOnlyList<string> ResolvedIpAddresses,
    string? ReverseDns,
    DateTime? RegistrationDate,
    DateTime? ExpirationDate,
    IReadOnlyList<string> NameServers,
    string? WhoisStatus,
    SubnetSearch.Core.Models.Network.HttpFingerprintResult? Http = null,
    string? DomainServiceType = null
);