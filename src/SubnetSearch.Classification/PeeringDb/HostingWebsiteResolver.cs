using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using System.Collections.Concurrent;

namespace SubnetSearch.Classification;

public class HostingWebsiteResolver : IWebsiteResolver
{
    private static readonly TimeSpan MaxEnrichmentTimeout = TimeSpan.FromSeconds(2);
    private readonly Dictionary<uint, string> _byAsn;
    private readonly Dictionary<string, string> _byOrg;
    private readonly PeeringDbWebsiteResolver? _peeringDbResolver;
    private readonly TimeSpan _enrichmentTimeout;
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
        PeeringDbWebsiteResolver? peeringDbResolver = null,
        TimeSpan? enrichmentTimeout = null)
    {
        _byAsn = byAsn ?? [];
        _byOrg = byOrg ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        _peeringDbResolver = peeringDbResolver;
        TimeSpan requestedTimeout = enrichmentTimeout ?? MaxEnrichmentTimeout;
        if (requestedTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(enrichmentTimeout));
        _enrichmentTimeout = requestedTimeout < MaxEnrichmentTimeout
            ? requestedTimeout
            : MaxEnrichmentTimeout;
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

    public async Task<PeeringDbNetworkInfo?> GetNetworkInfoFromPeeringDbAsync(
        uint asn,
        CancellationToken cancellationToken = default)
    {
        if (_peeringDbResolver == null)
            return null;

        cancellationToken.ThrowIfCancellationRequested();

        var lazy = _peeringDbCache.GetOrAdd(asn,
            key => new Lazy<Task<PeeringDbNetworkInfo?>>(
                () => FetchNetworkInfoAsync(key),
                LazyThreadSafetyMode.ExecutionAndPublication));
        Task<PeeringDbNetworkInfo?> sharedTask = lazy.Value;
        try
        {
            return await sharedTask.WaitAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (sharedTask.IsCanceled || sharedTask.IsFaulted)
                RemoveNetworkInfo(asn, lazy);
            throw;
        }
        catch (Exception exception) when (IsTransient(exception))
        {
            RemoveNetworkInfo(asn, lazy);
            return null;
        }
    }

    public async Task<IReadOnlyList<string>?> GetIxLocationsAsync(uint asn, CancellationToken cancellationToken = default)
    {
        if (_peeringDbResolver == null) return null;

        var info = await GetNetworkInfoFromPeeringDbAsync(asn, cancellationToken);
        if (info?.NetId is not int netId) return null;

        cancellationToken.ThrowIfCancellationRequested();
        var lazy = _ixLocationsCache.GetOrAdd(netId,
            key => new Lazy<Task<IReadOnlyList<string>?>>(
                () => FetchIxLocationsAsync(key),
                LazyThreadSafetyMode.ExecutionAndPublication));
        Task<IReadOnlyList<string>?> sharedTask = lazy.Value;
        try
        {
            return await sharedTask.WaitAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (sharedTask.IsCanceled || sharedTask.IsFaulted)
                RemoveIxLocations(netId, lazy);
            throw;
        }
        catch (Exception exception) when (IsTransient(exception))
        {
            RemoveIxLocations(netId, lazy);
            return null;
        }
    }

    private async Task<PeeringDbNetworkInfo?> FetchNetworkInfoAsync(uint asn)
    {
        using var timeout = new CancellationTokenSource(_enrichmentTimeout);
        return await _peeringDbResolver!.GetNetworkInfoForEnrichmentAsync(asn, timeout.Token);
    }

    private async Task<IReadOnlyList<string>?> FetchIxLocationsAsync(int netId)
    {
        using var timeout = new CancellationTokenSource(_enrichmentTimeout);
        return await _peeringDbResolver!.GetIxLocationsForEnrichmentAsync(netId, timeout.Token);
    }

    private void RemoveNetworkInfo(
        uint asn,
        Lazy<Task<PeeringDbNetworkInfo?>> failed)
    {
        if (_peeringDbCache.TryGetValue(asn, out var current) && ReferenceEquals(current, failed))
            _peeringDbCache.TryRemove(asn, out _);
    }

    private void RemoveIxLocations(
        int netId,
        Lazy<Task<IReadOnlyList<string>?>> failed)
    {
        if (_ixLocationsCache.TryGetValue(netId, out var current) && ReferenceEquals(current, failed))
            _ixLocationsCache.TryRemove(netId, out _);
    }

    private static bool IsTransient(Exception exception)
        => exception is HttpRequestException
            or System.Text.Json.JsonException
            or OperationCanceledException;
}
