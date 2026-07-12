using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using System.Text.RegularExpressions;

namespace SubnetSearch.Data;

public partial class DomainWhoisResolver : IDomainWhoisResolver
{
    [GeneratedRegex(@"refer:\s*([\w\.-]+)", RegexOptions.IgnoreCase)]
    private static partial Regex ReferralRegex();

    [GeneratedRegex(@"(?i)Registrar:\s*(.+)", RegexOptions.Multiline)]
    private static partial Regex RegistrarRegex();

    [GeneratedRegex(@"(?i)Creation Date:\s*(.+)", RegexOptions.Multiline)]
    private static partial Regex CreationDateRegex();

    [GeneratedRegex(@"(?i)Registered on:\s*(.+)", RegexOptions.Multiline)]
    private static partial Regex RegisteredOnRegex();

    [GeneratedRegex(@"(?i)Registry Expiry Date:\s*(.+)", RegexOptions.Multiline)]
    private static partial Regex RegistryExpiryRegex();

    [GeneratedRegex(@"(?i)Expiry Date:\s*(.+)", RegexOptions.Multiline)]
    private static partial Regex ExpiryDateRegex();

    [GeneratedRegex(@"(?i)Name Server:\s*(.+)", RegexOptions.Multiline)]
    private static partial Regex NameServerRegex();

    [GeneratedRegex(@"(?i)Domain Status:\s*(.+)", RegexOptions.Multiline)]
    private static partial Regex DomainStatusRegex();

    [GeneratedRegex(@"(?i)Status:\s*(.+)", RegexOptions.Multiline)]
    private static partial Regex StatusRegex();

    private static readonly Dictionary<string, string> DefaultServers = new()
    {
        { "com", "whois.internic.net" },
        { "org", "whois.pir.org" },
        { "ru",  "whois.ripn.net" }
    };

    public async Task<DomainWhoisResult> ResolveAsync(string domain, CancellationToken cancellationToken = default)
    {
        try
        {
            var tld = domain.Split('.').LastOrDefault()?.ToLowerInvariant();
            string whoisServer = "whois.iana.org";
            if (tld != null && DefaultServers.TryGetValue(tld, out var specificServer))
                whoisServer = specificServer;

            var ianaResponse = await WhoisQuery.SendAsync("whois.iana.org", domain, cancellationToken);
            var referral = ReferralRegex().Match(ianaResponse);
            if (referral.Success)
                whoisServer = referral.Groups[1].Value;

            var response = await WhoisQuery.SendAsync(whoisServer, domain, cancellationToken);

            string? registrar = null;
            DateTime? registrationDate = null;
            DateTime? expirationDate = null;
            var nameServers = new List<string>();
            string? whoisStatus = null;

            var regMatch = RegistrarRegex().Match(response);
            if (regMatch.Success)
                registrar = regMatch.Groups[1].Value.Trim();

            var creationMatch = CreationDateRegex().Match(response);
            if (creationMatch.Success && DateTime.TryParse(creationMatch.Groups[1].Value.Trim(), out var createDate))
                registrationDate = createDate;
            else
            {
                creationMatch = RegisteredOnRegex().Match(response);
                if (creationMatch.Success && DateTime.TryParse(creationMatch.Groups[1].Value.Trim(), out createDate))
                    registrationDate = createDate;
            }

            var expiryMatch = RegistryExpiryRegex().Match(response);
            if (expiryMatch.Success && DateTime.TryParse(expiryMatch.Groups[1].Value.Trim(), out var expiryDate))
                expirationDate = expiryDate;
            else
            {
                expiryMatch = ExpiryDateRegex().Match(response);
                if (expiryMatch.Success && DateTime.TryParse(expiryMatch.Groups[1].Value.Trim(), out expiryDate))
                    expirationDate = expiryDate;
            }

            foreach (Match ns in NameServerRegex().Matches(response))
            {
                var v = ns.Groups[1].Value.Trim();
                if (!string.IsNullOrWhiteSpace(v) && !nameServers.Contains(v))
                    nameServers.Add(v);
            }

            var statusMatch = DomainStatusRegex().Match(response);
            if (statusMatch.Success)
                whoisStatus = statusMatch.Groups[1].Value.Trim();
            else
            {
                statusMatch = StatusRegex().Match(response);
                if (statusMatch.Success)
                    whoisStatus = statusMatch.Groups[1].Value.Trim();
            }

            string rawPreview = response.Length > 500 ? response[..500] + "..." : response;

            return new DomainWhoisResult(
                Registrar: registrar,
                // The registrar is NOT the hosting provider — WHOIS carries the registrar only.
                // The real host is derived from the resolved IPs downstream (F3).
                HostingProvider: null,
                RegistrationDate: registrationDate,
                ExpirationDate: expirationDate,
                NameServers: nameServers.Count > 0 ? nameServers : null,
                WhoisStatus: whoisStatus,
                RawResponse: rawPreview);
        }
        catch
        {
            return new DomainWhoisResult(null, null, null, null, null, null, null);
        }
    }

}
