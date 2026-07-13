using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Classification;

public class DomainClassifier : IDomainClassifier
{
    private readonly IIpClassifier _ipClassifier;
    private readonly IDomainWhoisResolver _domainWhois;
    private readonly IDnsResolver _dnsResolver;
    private readonly bool _ownsIpClassifier;
    private int _disposed;

    public DomainClassifier(
        IIpClassifier ipClassifier,
        IDomainWhoisResolver domainWhois,
        IDnsResolver dnsResolver,
        bool ownsIpClassifier = false)
    {
        _ipClassifier = ipClassifier ?? throw new ArgumentNullException(nameof(ipClassifier));
        _domainWhois = domainWhois ?? throw new ArgumentNullException(nameof(domainWhois));
        _dnsResolver = dnsResolver ?? throw new ArgumentNullException(nameof(dnsResolver));
        _ownsIpClassifier = ownsIpClassifier;
    }

    public async Task<DomainClassificationResult> ClassifyDomainAsync(string domain, CancellationToken cancellationToken = default)
    {
        var ips = await _dnsResolver.ResolveAllIpAsync(domain, cancellationToken);
        var ipAddresses = ips.Select(ip => ip.ToString()).ToList();

        // IP classification, reverse DNS and domain WHOIS run in parallel.
        // ToList() materialises the tasks once; without it Select() would re-run ClassifyAsync.
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

        // Domain WHOIS identifies the registrar, not the hosting provider.
        string? hostingProvider = ipResults.FirstOrDefault(r => r.IsHosting)?.Organization
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

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        if (_ownsIpClassifier) _ipClassifier.Dispose();
    }
}
