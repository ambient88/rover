using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Network;

public class ProviderScanner : IProviderScanner
{
    private readonly RipeStatClient   _ripeStat;
    private readonly IWebsiteResolver _websiteResolver;
    private readonly IIpRangeIndex?   _ipIndex; 

    public ProviderScanner(
        RipeStatClient   ripeStat,
        IWebsiteResolver websiteResolver,
        IIpRangeIndex?   ipIndex = null)
    {
        _ripeStat        = ripeStat        ?? throw new ArgumentNullException(nameof(ripeStat));
        _websiteResolver = websiteResolver ?? throw new ArgumentNullException(nameof(websiteResolver));
        _ipIndex         = ipIndex;
    }

    public async Task<ProviderScanResult?> ScanAsync(string query, CancellationToken cancellationToken = default)
    {
        var (asn, candidates) = await ResolveAsnAsync(query, cancellationToken);
        if (asn == 0) return null;

        var overviewTask  = _ripeStat.GetAsnOverviewAsync(asn, cancellationToken);
        var prefixTask    = _ripeStat.GetPrefixesAsync(asn, cancellationToken);
        var upstreamTask  = _ripeStat.GetUpstreamAsnsAsync(asn, cancellationToken);
        var pdbTask       = _websiteResolver.GetNetworkInfoFromPeeringDbAsync(asn, cancellationToken);

        await Task.WhenAll(overviewTask, prefixTask, upstreamTask, pdbTask);

        var overview       = overviewTask.Result;
        var prefixStrings  = prefixTask.Result;
        var upstreamAsns   = upstreamTask.Result;
        var pdbInfo        = pdbTask.Result;

        var upstreamNamesTask = _ripeStat.GetUpstreamsAsync(upstreamAsns, cancellationToken);
        var ixTask = pdbInfo?.NetId.HasValue == true
            ? _websiteResolver.GetIxLocationsAsync(asn, cancellationToken)
            : Task.FromResult<IReadOnlyList<string>?>(null);

        await Task.WhenAll(upstreamNamesTask, ixTask);

        var upstreams   = (IReadOnlyList<ProviderUpstream>)upstreamNamesTask.Result;
        var ixLocations = ixTask.Result;

        var prefixes = prefixStrings
            .Select(p => EnrichPrefix(p))
            .OrderBy(p => p.CountryCode ?? "ZZ")
            .ThenByDescending(p => p.IpCount)
            .ToList();

        var (handle, org) = ParseHolder(overview?.Holder);

        string? website = string.IsNullOrWhiteSpace(pdbInfo?.Website)
            ? null
            : pdbInfo.Website;

        long totalIps = prefixes.Sum(p => p.IpCount);

        var otherCandidates = candidates.Count > 1
            ? candidates.Skip(1)
                .Select(c => (c.Asn, (string?)null, c.Description))
                .ToList<(uint, string?, string?)>()
            : null;

        return new ProviderScanResult(
            Asn:             asn,
            AsnHandle:       handle,
            Organization:    org,
            Website:         website,
            InfoType:        pdbInfo?.InfoType,
            CountryCode:     null,
            PeeringCount:    pdbInfo?.IxCount,
            IxLocations:     ixLocations,
            Prefixes:        prefixes,
            Upstreams:       upstreams,
            TotalIpCount:    totalIps,
            OtherCandidates: otherCandidates
        );
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private IpPrefix EnrichPrefix(string prefix)
    {
        long ipCount = CalcIpCount(prefix);

        if (_ipIndex == null)
            return new IpPrefix(prefix, null, null, ipCount);
        var slash = prefix.IndexOf('/');
        string ipStr = slash >= 0 ? prefix[..slash] : prefix;

        if (!IpConverter.TryIpToUint(ipStr, out uint ipInt))
            return new IpPrefix(prefix, null, null, ipCount);

        var record = _ipIndex.Find(ipInt);
        return new IpPrefix(
            prefix,
            record.HasValue ? record.Value.Country : null,
            record.HasValue ? record.Value.Description : null,
            ipCount);
    }

    internal static long CalcIpCount(string prefix)
    {
        var slash = prefix.IndexOf('/');
        if (slash < 0 || !int.TryParse(prefix.AsSpan(slash + 1), out int cidr) || cidr < 0 || cidr > 32) return 0;
        // Exact power of two via shift: 1L << 32 (a /0) = 4_294_967_296, which fits in long
        // but not int. Avoids the (int)Math.Pow overflow that made /1 and /0 go negative (F20).
        return 1L << (32 - cidr);
    }

    // "SENKO-AS Senko Digital LLC" → ("SENKO-AS", "Senko Digital LLC")
    internal static (string? Handle, string? Org) ParseHolder(string? holder)
    {
        if (string.IsNullOrWhiteSpace(holder)) return (null, null);
        var idx = holder.IndexOf(' ');
        if (idx < 0) return (holder, null);
        return (holder[..idx], holder[(idx + 1)..].Trim());
    }

    // ── ASN resolution ────────────────────────────────────────────────────────

    private async Task<(uint Asn, IReadOnlyList<RipeStatClient.SearchResult> Candidates)>
        ResolveAsnAsync(string query, CancellationToken ct)
    {
        query = query.Trim();

        string numStr = query.StartsWith("AS", StringComparison.OrdinalIgnoreCase)
            ? query[2..] : query;

        if (uint.TryParse(numStr, out uint directAsn))
            return (directAsn, []);

        var results = await _ripeStat.SearchAsync(query, ct);
        if (results.Count == 0) return (0, []);

        return (results[0].Asn, results);
    }
}
