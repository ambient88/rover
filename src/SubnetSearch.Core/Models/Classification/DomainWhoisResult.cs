namespace SubnetSearch.Core.Models.Classification;

public record DomainWhoisResult(
    string? Registrar,
    string? HostingProvider,
    DateTime? RegistrationDate,
    DateTime? ExpirationDate,
    IReadOnlyList<string>? NameServers,
    string? WhoisStatus,
    string? RawResponse
);
