using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Classification;

public class DomainClassifier : IDomainClassifier
{
    private readonly IIpClassifier _ipClassifier;
    private readonly IDomainWhoisResolver _domainWhois;
    private readonly IDnsResolver _dnsResolver;

    public DomainClassifier(IIpClassifier ipClassifier, IDomainWhoisResolver domainWhois, IDnsResolver dnsResolver)
    {
        _ipClassifier = ipClassifier ?? throw new ArgumentNullException(nameof(ipClassifier));
        _domainWhois = domainWhois ?? throw new ArgumentNullException(nameof(domainWhois));
        _dnsResolver = dnsResolver ?? throw new ArgumentNullException(nameof(dnsResolver));
    }

    public async Task<DomainClassificationResult> ClassifyDomainAsync(string domain, CancellationToken cancellationToken = default)
    {
        var ips = await _dnsResolver.ResolveAllIpAsync(domain, cancellationToken);
        var ipAddresses = ips.Select(ip => ip.ToString()).ToList();

        // Классификация IP, reverse DNS и WHOIS домена запускаются параллельно.
        // ToList() материализует задачи один раз — без него Select() запустит ClassifyAsync повторно.
        var classifyTasks = ipAddresses.Select(ip => _ipClassifier.ClassifyAsync(ip, cancellationToken)).ToList();
        var reverseDnsTask = ips.Count > 0
            ? _dnsResolver.ReverseDnsAsync(ips[0], cancellationToken)
            : Task.FromResult<string?>(null);
        var domainWhoisTask = _domainWhois.ResolveAsync(domain, cancellationToken);

        await Task.WhenAll(
            Task.WhenAll(classifyTasks),
            reverseDnsTask,
            domainWhoisTask);

        var ipResults = (await Task.WhenAll(classifyTasks)).ToList();
        string? reverseDns = await reverseDnsTask;
        var domainWhois = await domainWhoisTask;

        // If WHOIS didn't return a hosting provider, derive it from IP results.
        string? hostingProvider = domainWhois.HostingProvider;
        if (string.IsNullOrWhiteSpace(hostingProvider))
            hostingProvider = ipResults.FirstOrDefault(r => r.IsHosting)?.Organization
                           ?? ipResults.FirstOrDefault()?.Organization;

        return new DomainClassificationResult(
            Domain: domain,
            IpResults: ipResults,
            DomainRegistrar: domainWhois.Registrar,
            DomainHostingProvider: hostingProvider,
            ResolvedIpAddresses: ipAddresses,
            ReverseDns: reverseDns,
            RegistrationDate: domainWhois.RegistrationDate,
            ExpirationDate: domainWhois.ExpirationDate,
            NameServers: domainWhois.NameServers ?? Array.Empty<string>(),
            WhoisStatus: domainWhois.WhoisStatus,
            DomainServiceType: DetectServiceType(domain)
        );
    }

    // Detects if the domain itself appears to offer hosting/proxy services
    // by scanning root-level domain labels for known service keywords.
    private static string? DetectServiceType(string domain)
    {
        var labels = domain.ToLowerInvariant().Split('.');
        // Ignore TLD (last label). If only one label exists, nothing meaningful to check.
        if (labels.Length <= 1) return null;
        var meaningful = labels[..^1];
        foreach (var label in meaningful)
            foreach (var (keyword, type) in ServiceKeywords)
                if (label.Contains(keyword))
                    return type;
        return null;
    }

    private static readonly (string Keyword, string Label)[] ServiceKeywords =
    [
        ("proxy",       "Proxy service"),
        ("vpn",         "VPN service"),
        ("hosting",     "Hosting service"),
        ("vps",         "VPS service"),
        ("cloud",       "Cloud service"),
        ("cdn",         "CDN service"),
        ("ddos",        "DDoS protection"),
        ("server",      "Server service"),
        ("dedicated",   "Dedicated server service"),
    ];
}
