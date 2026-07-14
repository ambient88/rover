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
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(TimeSpan.FromSeconds(7));
        var budgetToken = budget.Token;

        (uint asn, IReadOnlyList<RipeStatClient.SearchResult> candidates) resolved;
        try
        {
            resolved = await ResolveAsnAsync(query, budgetToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        var (asn, candidates) = resolved;
        if (asn == 0) return null;

        var overviewTask  = _ripeStat.GetAsnOverviewAsync(asn, budgetToken);
        var prefixTask    = _ripeStat.GetPrefixesAsync(asn, budgetToken);
        var upstreamTask  = _ripeStat.GetUpstreamAsnsAsync(asn, budgetToken);
        var pdbTask       = _websiteResolver.GetNetworkInfoFromPeeringDbAsync(asn, budgetToken);

        try
        {
            await Task.WhenAll(overviewTask, prefixTask, upstreamTask, pdbTask);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
        }

        var overview       = overviewTask.IsCompletedSuccessfully ? overviewTask.Result : null;
        var prefixStrings  = prefixTask.IsCompletedSuccessfully ? prefixTask.Result : [];
        var upstreamAsns   = upstreamTask.IsCompletedSuccessfully ? upstreamTask.Result : [];
        var pdbInfo        = pdbTask.IsCompletedSuccessfully ? pdbTask.Result : null;

        var upstreamNamesTask = _ripeStat.GetUpstreamsAsync(upstreamAsns, budgetToken);
        var ixTask = pdbInfo?.NetId.HasValue == true
            ? _websiteResolver.GetIxLocationsAsync(asn, budgetToken)
            : Task.FromResult<IReadOnlyList<string>?>(null);

        try
        {
            await Task.WhenAll(upstreamNamesTask, ixTask);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
        }

        var upstreams = upstreamNamesTask.IsCompletedSuccessfully
            ? (IReadOnlyList<ProviderUpstream>)upstreamNamesTask.Result
            : [];
        var ixLocations = ixTask.IsCompletedSuccessfully ? ixTask.Result : null;

        var prefixes = prefixStrings
            .Select(p => EnrichPrefix(p))
            .OrderBy(p => p.CountryCode ?? "ZZ")
            .ThenByDescending(p => p.IpCount)
            .ToList();

        var (handle, org) = ParseHolder(overview?.Holder);

        string? website = string.IsNullOrWhiteSpace(pdbInfo?.Website)
            ? null
            : pdbInfo.Website;

        long totalIps = Ipv4RangeMath.CountUniqueAddresses(prefixStrings);

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

    // Helper methods.

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
        => Ipv4RangeMath.CountAddresses(prefix);

    // Split "SENKO-AS Senko Digital LLC" into the handle and organization name.
    internal static (string? Handle, string? Org) ParseHolder(string? holder)
    {
        if (string.IsNullOrWhiteSpace(holder)) return (null, null);
        var idx = holder.IndexOf(' ');
        if (idx < 0) return (holder, null);
        return (holder[..idx], holder[(idx + 1)..].Trim());
    }

    // ASN resolution.

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
