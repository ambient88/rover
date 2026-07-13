using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using System.Collections.Concurrent;

namespace SubnetSearch.Classification;

public class HostingWebsiteResolver : IWebsiteResolver
{
    private readonly Dictionary<uint, string> _byAsn;
    private readonly Dictionary<string, string> _byOrg;
    private readonly PeeringDbWebsiteResolver? _peeringDbResolver;
    private readonly ConcurrentDictionary<string, SubstringResult> _substringCache = new(StringComparer.Ordinal);

    private readonly record struct SubstringResult(string? Website);

    // Cache holds the full PeeringDB response; website and info_type are extracted from it.
    private readonly ConcurrentDictionary<uint, Lazy<Task<PeeringDbNetworkInfo?>>> _peeringDbCache = new();
    // IX locations are keyed by PeeringDB net_id (not ASN) but deduplicated the same way.
    private readonly ConcurrentDictionary<int, Lazy<Task<IReadOnlyList<string>?>>> _ixLocationsCache = new();

    private static readonly Dictionary<string, string> ManualOverrides = new(StringComparer.OrdinalIgnoreCase)
    {
        { "AMAZON",           "https://aws.amazon.com" },
        { "DIGITALOCEAN",     "https://www.digitalocean.com" },
        { "HETZNER",          "https://www.hetzner.com" },
        { "OVH",              "https://www.ovhcloud.com" },
        { "LINODE",           "https://www.linode.com" },
        { "CLOUDFLARE",       "https://www.cloudflare.com" },
        { "TIMEWEB",          "https://timeweb.com" },
        { "BEGET",            "https://beget.com" },
        { "REG.RU",           "https://reg.ru" },
        { "VSCALE",           "https://vscale.io" },
        { "SELECTEL",         "https://selectel.ru" },
        { "DDOS-GUARD",       "https://ddos-guard.net" },
        { "YANDEXCLOUD",      "https://cloud.yandex.com" },
        { "YANDEX.CLOUD LLC", "https://cloud.yandex.com" },
    };

    public HostingWebsiteResolver(
        Dictionary<uint, string> byAsn,
        Dictionary<string, string> byOrg,
        PeeringDbWebsiteResolver? peeringDbResolver = null)
    {
        _byAsn = byAsn ?? [];
        _byOrg = byOrg ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        _peeringDbResolver = peeringDbResolver;
    }

    public string? GetWebsite(uint? asn, string? organization, string? whoisWebsite = null)
    {
        if (!string.IsNullOrWhiteSpace(whoisWebsite))
            return whoisWebsite;

        if (asn.HasValue && _byAsn.TryGetValue(asn.Value, out var site))
            return site;

        if (!string.IsNullOrWhiteSpace(organization) && _byOrg.TryGetValue(organization, out site))
            return site;

        if (!string.IsNullOrWhiteSpace(organization) && ManualOverrides.TryGetValue(organization, out site))
            return site;

        if (!string.IsNullOrWhiteSpace(organization))
            return _substringCache.GetOrAdd(
                organization,
                FindBySubstring).Website;

        return null;
    }

    private SubstringResult FindBySubstring(string organization)
    {
        foreach (var pair in ManualOverrides)
            if (organization.Contains(pair.Key, StringComparison.OrdinalIgnoreCase))
                return new SubstringResult(pair.Value);

        foreach (var pair in _byOrg)
            if (organization.Contains(pair.Key, StringComparison.OrdinalIgnoreCase))
                return new SubstringResult(pair.Value);

        return new SubstringResult(null);
    }

    public Task<PeeringDbNetworkInfo?> GetNetworkInfoFromPeeringDbAsync(uint asn, CancellationToken cancellationToken = default)
    {
        if (_peeringDbResolver == null)
            return Task.FromResult<PeeringDbNetworkInfo?>(null);

        var lazy = _peeringDbCache.GetOrAdd(asn,
            key => new Lazy<Task<PeeringDbNetworkInfo?>>(
                // CancellationToken.None: the cached Task must outlive any single caller's
                // cancellation so subsequent lookups for the same ASN reuse the result.
                () => _peeringDbResolver.GetNetworkInfoAsync(key, CancellationToken.None),
                LazyThreadSafetyMode.ExecutionAndPublication));
        return lazy.Value;
    }

    public async Task<IReadOnlyList<string>?> GetIxLocationsAsync(uint asn, CancellationToken cancellationToken = default)
    {
        if (_peeringDbResolver == null) return null;

        var info = await GetNetworkInfoFromPeeringDbAsync(asn, cancellationToken);
        if (info?.NetId is not int netId) return null;

        // Cache per net_id with the same Lazy<Task> deduplication pattern as _peeringDbCache.
        // Without this, batch classification of a large CIDR in one ASN fires the same
        // ?netixlan?net_id=... request for every IP in parallel — typically hundreds of times.
        var lazy = _ixLocationsCache.GetOrAdd(netId,
            key => new Lazy<Task<IReadOnlyList<string>?>>(
                () => _peeringDbResolver.GetIxLocationsAsync(key, CancellationToken.None),
                LazyThreadSafetyMode.ExecutionAndPublication));
        return await lazy.Value;
    }
}
