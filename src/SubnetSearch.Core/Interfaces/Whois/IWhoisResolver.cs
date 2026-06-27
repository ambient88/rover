namespace SubnetSearch.Core.Interfaces.Whois;

public interface IWhoisResolver
{
    Task<WhoisResult?> ResolveAsync(string ipAddress, CancellationToken cancellationToken = default);
}

public record WhoisResult(
    string? Organization,
    string? Country,
    string? Website,
    DateTime? RegistrationDate,
    DateTime? UpdatedDate,
    string? Status,
    string? RawResponse,
    string? AbuseEmail = null,
    string? Rir = null
);