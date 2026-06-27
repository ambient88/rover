using SubnetSearch.Core.Interfaces.Whois;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace SubnetSearch.Data;

public partial class WhoisResolver : IWhoisResolver
{
    private const int TimeoutSeconds = 30;
    private readonly ConcurrentDictionary<string, Lazy<Task<WhoisResult?>>> _cache = new();
    [GeneratedRegex(@"refer:\s*([\w\.-]+)", RegexOptions.IgnoreCase)]
    private static partial Regex ReferralRegex();

    [GeneratedRegex(@"^(?<field>[^:]+):\s*(?<value>.+?)\s*$", RegexOptions.Multiline)]
    private static partial Regex FieldRegex();

    [GeneratedRegex(@"^[Cc]ountry:\s*(\w\w)", RegexOptions.Multiline)]
    private static partial Regex CountryRegex();

    [GeneratedRegex(@"(?i)website:\s*(https?://[^\s]+)")]
    private static partial Regex WebsiteFieldRegex();

    [GeneratedRegex(@"(?i)remarks:\s*website\s+?(https?://[^\s]+)")]
    private static partial Regex WebsiteRemarksRegex();

    [GeneratedRegex(@"(?:https?://)?(www\.[^\s]+\.[a-z]{2,}(?:/[^\s]*)?)")]
    private static partial Regex WebsiteWwwRegex();

    [GeneratedRegex(@"(?i)status:\s*(.+)", RegexOptions.Multiline)]
    private static partial Regex StatusRegex();

    [GeneratedRegex(@"(?i)(?:abuse-mailbox|OrgAbuseEmail|abuse-c.*?Email):\s*([\w.+\-]+@[\w.\-]+)", RegexOptions.Multiline)]
    private static partial Regex AbuseEmailRegex();

    private static readonly Dictionary<string, string> WhoisServerToRir = new(StringComparer.OrdinalIgnoreCase)
    {
        { "whois.arin.net",    "ARIN"    },
        { "whois.ripe.net",    "RIPE"    },
        { "whois.apnic.net",   "APNIC"   },
        { "whois.lacnic.net",  "LACNIC"  },
        { "whois.afrinic.net", "AFRINIC" },
    };

    private static readonly Dictionary<string, string[]> RirOrgFields = new()
    {
        { "whois.arin.net",    ["OrgName", "CustName", "Organization"] },
        { "whois.ripe.net",    ["org-name", "descr", "org", "netname"] },
        { "whois.apnic.net",   ["descr", "org", "netname"] },
        { "whois.lacnic.net",  ["owner", "responsible"] },
        { "whois.afrinic.net", ["descr", "org", "netname"] }
    };

    // The external CancellationToken is intentionally not forwarded: the cached Task
    // must remain valid after the caller is cancelled so subsequent calls can reuse it.
    public Task<WhoisResult?> ResolveAsync(string ipAddress, CancellationToken cancellationToken = default)
    {
        var lazy = _cache.GetOrAdd(ipAddress,
            ip => new Lazy<Task<WhoisResult?>>(() => ResolveInternalAsync(ip),
                LazyThreadSafetyMode.ExecutionAndPublication));
        return lazy.Value;
    }

    private async Task<WhoisResult?> ResolveInternalAsync(string ipAddress)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(TimeoutSeconds));
        try
        {
            var ianaResponse = await WhoisQuery.SendAsync("whois.iana.org", ipAddress, cts.Token);
            var referral = ReferralRegex().Match(ianaResponse);
            string whoisServer = referral.Success ? referral.Groups[1].Value : "whois.ripe.net";

            var response = await WhoisQuery.SendAsync(whoisServer, ipAddress, cts.Token);

            string? organization = null;
            if (RirOrgFields.TryGetValue(whoisServer, out var fields))
            {
                foreach (var field in fields)
                {
                    var match = Regex.Match(response,
                        $@"^{Regex.Escape(field)}:\s*(.+?)\s*$",
                        RegexOptions.Multiline | RegexOptions.IgnoreCase);
                    if (match.Success)
                    {
                        organization = match.Groups[1].Value.Trim();
                        break;
                    }
                }
            }

            string? country = null;
            var countryMatch = CountryRegex().Match(response);
            if (countryMatch.Success)
                country = countryMatch.Groups[1].Value.ToUpperInvariant();

            string? website = ExtractDomain(response);
            string? abuseEmail = ExtractAbuseEmail(response);
            WhoisServerToRir.TryGetValue(whoisServer, out string? rir);

            DateTime? registrationDate = ExtractDate(response, "Registration");
            DateTime? updatedDate = ExtractDate(response, "Updated");
            string? status = ExtractStatus(response);

            string rawPreview = response.Length > 500 ? response[..500] + "..." : response;

            return new WhoisResult(organization, country, website, registrationDate, updatedDate, status, rawPreview,
                AbuseEmail: abuseEmail, Rir: rir);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception)
        {
            // Network errors, parse failures, or WHOIS server issues are non-fatal.
            // Return null so callers fall through to the next classification layer.
            return null;
        }
    }

    // RIR/IANA domains that appear in boilerplate WHOIS text and are not
    // the website of the organization being looked up.
    private static readonly HashSet<string> RegistryDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "arin.net", "ripe.net", "apnic.net", "lacnic.net", "afrinic.net",
        "iana.org", "nro.net", "rdap.arin.net"
    };

    private string? ExtractAbuseEmail(string whoisResponse)
    {
        var match = AbuseEmailRegex().Match(whoisResponse);
        return match.Success ? match.Groups[1].Value.Trim() : null;
    }

    private string? ExtractDomain(string whoisResponse)
    {
        foreach (var regex in new[] { WebsiteFieldRegex(), WebsiteRemarksRegex(), WebsiteWwwRegex() })
        {
            var match = regex.Match(whoisResponse);
            if (!match.Success) continue;

            string candidate = match.Groups[1].Value.Trim();
            if (candidate.Contains('@')) continue;
            if (!candidate.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                candidate = "https://" + candidate;
            if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri)) continue;
            if (RegistryDomains.Any(d => uri.Host.EndsWith(d, StringComparison.OrdinalIgnoreCase))) continue;
            return uri.AbsoluteUri;
        }
        return null;
    }

    private static DateTime? ExtractDate(string whoisResponse, string fieldName)
    {
        var match = Regex.Match(whoisResponse,
            $@"(?i){Regex.Escape(fieldName)}.*?(\d{{4}}-\d{{2}}-\d{{2}})",
            RegexOptions.Multiline);
        return match.Success && DateTime.TryParse(match.Groups[1].Value, out var date) ? date : null;
    }

    private string? ExtractStatus(string whoisResponse)
    {
        var match = StatusRegex().Match(whoisResponse);
        return match.Success ? match.Groups[1].Value.Trim() : null;
    }

}
