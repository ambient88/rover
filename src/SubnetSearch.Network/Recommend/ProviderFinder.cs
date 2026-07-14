using System.Text.Json;
using SubnetSearch.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Models.Network;
using SubnetSearch.Core.Utilities;
using SubnetSearch.Network.Http;

namespace SubnetSearch.Network.Recommend;

public record ProviderCandidate(
    uint    Asn,
    string  Name,
    string? Country,
    string? Website,
    string? InfoType,
    int?    PeeringCount,
    IReadOnlyList<string>? IxLocations,
    IReadOnlyList<string>  Prefixes,
    double? RpkiScore       = null,
    long    TotalIpCount    = 0,
    bool    HasIPv6         = false,
    int     IPv6PrefixCount = 0,
    int     UpstreamCount   = 0,
    int     CoverageCount   = 0
);

public class ProviderFinder(
    HttpClient      peeringDbHttp,
    RipeStatClient  ripeClient,
    // AsnTypeResolver builds a local type map from as.json and bgp.tools tags.
    // This replaces network calls to ipapi.is for provider type filtering.
    // zero quota, works offline, and the source can never be unavailable.
    IReadOnlyDictionary<uint, string>? asnTypes = null,
    AsnExclusions?  exclusions            = null,
    BgpViewClient?  bgpView               = null,
    string?         cacheDir              = null,
    IReadOnlyDictionary<uint, string>? caidaClassifications = null,
    RipeStatCache?  ripeCache             = null,
    // The PeeringDB key is attached to individual requests.
    string?         peeringDbKey          = null,
    IReadOnlyList<Ip2AsnRecord>? localIp2AsnRecords = null)
{
    private readonly AsnExclusions  _excl      = exclusions ?? AsnExclusions.Default;
    private readonly BgpViewClient? _bgpView   = bgpView;
    private readonly string?        _cacheDir  = cacheDir;
    private readonly RipeStatCache? _ripeCache = ripeCache;
    private readonly IReadOnlyDictionary<uint, string>? _caida = caidaClassifications;
    private readonly IReadOnlyDictionary<uint, string>? _asnTypes = asnTypes;
    private readonly IReadOnlyList<Ip2AsnRecord>? _localIp2AsnRecords = localIp2AsnRecords;
    private readonly string? _pdbKey = PeeringDbAuth.Sanitize(peeringDbKey);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, PeeringDbCacheFile>
        _peeringDbMemoryCache = new(StringComparer.OrdinalIgnoreCase);

    private string? LookupAsnType(uint asn)
        => _asnTypes != null && _asnTypes.TryGetValue(asn, out var t) ? t : null;

    private const string PeeringDbBase = "https://www.peeringdb.com/api";

    /// <summary>
    /// Builds an authenticated PeeringDB request when a key is configured.
    /// </summary>
    private HttpRequestMessage PdbRequest(string url)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (_pdbKey != null)
            req.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Api-Key", _pdbKey);
        return req;
    }

    // Maps user-friendly --type aliases to PeeringDB info_type values (case-sensitive).
    // Returns null for an unrecognized value so the caller can report invalid input.
    //
    // PeeringDB currently has no providers with info_type="Hosting".
    // VPS/dedicated providers (Hetzner, OVH, Linode, DigitalOcean) are all "Content".
    // CDN providers (Cloudflare, Akamai, Fastly) are also "Content".
    // Some cloud providers (Yandex Cloud, etc.) use "Enterprise".
    // Distinction within "Content" is done by ExcludeCdn flag via name/ASN heuristics.
    public static string[]? ResolveInfoTypes(string? typeFilter) => typeFilter?.ToLowerInvariant() switch
    {
        null                                                                    => null,
        "server" or "hosting" or "vps" or "dedicated" or "cloud"               => ["Content", "NSP", "Enterprise"],
        "cdn"    or "content"                                                   => ["Content"],
        "nsp"    or "isp"     or "transit"                                      => ["NSP"],
        "ai"                                                                    => ["Content", "NSP", "Enterprise"],
        _                                                                       => null,
    };

    // When --type server (and its aliases) is used, exclude pure CDN and AI providers from results.
    public static bool ShouldExcludeCdn(string? typeFilter) =>
        typeFilter?.ToLowerInvariant() is "server" or "hosting" or "vps" or "dedicated" or "cloud";

    // When --type ai is used, only show known AI/GPU providers.
    public static bool ShouldFilterAiOnly(string? typeFilter) =>
        typeFilter?.ToLowerInvariant() is "ai";

    // When --type server (and aliases) is used, exclude pure AI/GPU-only providers.
    public static bool ShouldExcludeAi(string? typeFilter) =>
        typeFilter?.ToLowerInvariant() is "server" or "hosting" or "vps" or "dedicated" or "cloud";

    // Allowlist membership for server types (replaces ApplyTaxonomyFilter): a candidate stays
    // A provider passes only when it belongs to the curated core for that type.
    // For non-server typeFilter (cdn/nsp/ai/null-as-"not server") it returns the input unchanged.
    public static IReadOnlyList<ProviderCandidate> ApplyServerAllowlist(
        IReadOnlyList<ProviderCandidate> candidates,
        string? typeFilter,
        ServerProviders serverProviders)
    {
        if (!IsServerTypeFilter(typeFilter)) return candidates;
        // typeFilter arrives raw (case is not normalized upstream). hosting is the documented
        // Normalize case and treat hosting as an alias for server membership.
        var t = typeFilter!.ToLowerInvariant();
        if (t == "hosting") t = "server";
        return [.. candidates.Where(c => serverProviders.IsAllowed(c.Asn, t))];
    }

    // The server family of filters the allowlist applies to (hosting is an alias for server).
    public static bool IsServerTypeFilter(string? typeFilter) =>
        typeFilter?.ToLowerInvariant() is "server" or "hosting" or "vps" or "dedicated" or "cloud";

    // The core-first candidate source applies only to the global server type without --from:
    // then candidates come from the core rather than a broad PeeringDB pull.
    public static bool UseCoreFirstSource(string? typeFilter, string? region, bool hasFromList) =>
        IsServerTypeFilter(typeFilter) && string.IsNullOrWhiteSpace(region) && !hasFromList;

    // Keeps only ASNs whose country set (from ip2asn) intersects the requested codes.
    // An empty country list preserves the input without network access.
    public static IReadOnlyList<uint> FilterAsnsByCountry(
        IEnumerable<uint> asns,
        IReadOnlyDictionary<uint, HashSet<string>> asnToCountries,
        string[] countryCodes)
    {
        if (countryCodes is not { Length: > 0 }) return [.. asns];
        var wanted = new HashSet<string>(countryCodes, StringComparer.OrdinalIgnoreCase);
        return [.. asns.Where(a =>
            asnToCountries.TryGetValue(a, out var cs) && cs.Any(wanted.Contains))];
    }

    public const string ValidTypeValues =
        "server                        — all server rental: VPS ∪ dedicated ∪ cloud [alias: hosting]\n" +
        "                         vps              — rentable VPS providers (curated core only)\n" +
        "                         dedicated        — bare-metal / dedicated providers (curated core)\n" +
        "                         cloud            — hyperscalers only (AWS, Azure, GCP, ... — curated core)\n" +
        "                         cdn / content    — CDN and content networks\n" +
        "                         nsp / isp / transit  — Network service providers\n" +
        "                         ai               — AI/GPU-only cloud providers (CoreWeave, Lambda, Crusoe, etc.)";

    private bool IsNonHostingProvider(ProviderCandidate c) => _excl.NonHostingAsns.Contains(c.Asn);
    private bool IsCdnProvider(ProviderCandidate c)        => _excl.KnownCdnAsns.Contains(c.Asn);
    private bool IsAiProvider(ProviderCandidate c)         => _excl.KnownAiProviderAsns.Contains(c.Asn);

    // Pure decision for a candidate whose local ASN type is neither "hosting" nor "cloud"
    // without I/O, which keeps it fully testable. CAIDA and NSP checks apply regardless of the local IP range
    // whitelist (ipcat/cloud-provider/server-ip datasets flag "this address block sits in a
    // datacenter" rather than "this organization sells retail VPS or dedicated servers." A wholesale transit
    // carrier's own infrastructure runs through datacenters too). Before this rule, whitelist
    // membership alone let large NSP-classified carriers through unconditionally: Hurricane
    // Electric, Colt, Equinix, M247, DataBank all slipped past as "vps" this way. Whitelist
    // only grants benefit of doubt as the last, weakest check (small/unclassified Content nets).
    public static bool ShouldIncludeUnverifiedHostingCandidate(
        string? infoType, string? caidaClassification, bool inWhitelist,
        long totalIpCount, bool strictContentFilter)
    {
        if (caidaClassification is "Enterprise" or "Transit/Access") return false;
        if (string.Equals(infoType, "NSP", StringComparison.OrdinalIgnoreCase)) return false;
        return inWhitelist || (!strictContentFilter && totalIpCount >= 1024);
    }

    // Global search: fetches all hosting/content networks from PeeringDB directly.
    // Returns top candidates sorted by peering count, enriched with prefixes.
    // onPreEnrichment: called with (perTypeCounts, errors, totalBeforeEnrich) for diagnostics.
    // countryCodes: optional list of ISO country codes to filter by (e.g. ["DE","NL","FI"]).
    public async Task<IReadOnlyList<ProviderCandidate>> FindGlobalAsync(
        string[]? countryCodes = null,
        int topN = 300,
        string[]? infoTypes = null,
        bool excludeCdn = false,
        bool excludeAi = false,
        bool aiOnly = false,
        HashSet<uint>? localHostingWhitelist = null,
        Action<Dictionary<string, int>, IReadOnlyList<string>, int>? onPreEnrichment = null,
        Action<string>? onStatus = null,
        CancellationToken ct = default)
    {
        // PeeringDB info_type values are case-sensitive: "Content", "NSP".
        // "Hosting" is omitted because PeeringDB has no networks with that type.
        // Requests are sequential to avoid triggering PeeringDB rate limits from parallel bursts.
        var types   = infoTypes ?? ["Content", "NSP"];
        var fetches = (await Task.WhenAll(types.Select(
            type => FetchNetsByTypeAsync(type, ct, onStatus)))).ToList();

        var perType = types.Zip(fetches).ToDictionary(p => p.First, p => p.Second.Candidates.Count);
        var errors  = fetches.Select(f => f.Error).OfType<string>().ToList();

        var byType = types.Zip(fetches).ToDictionary(p => p.First, p => p.Second.Candidates);

        // Enterprise networks are small in number (~2425 total) and include legitimate cloud
        // providers (e.g. Yandex Cloud) with low peering counts that topN would exclude.
        // Include ALL Enterprise networks; apply topN only to Content and NSP.
        var enterprise = byType.TryGetValue("Enterprise", out var ent) ? ent : [];
        var nonEnterprise = byType
            .Where(kv => kv.Key != "Enterprise")
            .SelectMany(kv => kv.Value)
            .DistinctBy(n => n.Asn);

        var all = nonEnterprise
            .OrderByDescending(n => n.PeeringCount ?? 0)
            .Take(topN)
            .Concat(enterprise)
            .DistinctBy(n => n.Asn);

        // PeeringDB bulk /api/net does not return a country field, so client-side
        // country filtering here would eliminate all candidates. Country is looked up from
        // ip2asn in HandleRecommend after enrichment, then the post-filter is applied there.

        // Always remove companies that don't offer commercial hosting (Apple, Netflix, Meta)
        all = all.Where(n => !IsNonHostingProvider(n));
        if (excludeCdn)
            all = all.Where(n => !IsCdnProvider(n));
        if (excludeAi)
            all = all.Where(n => !IsAiProvider(n));
        if (aiOnly)
            all = all.Where(n => IsAiProvider(n));

        var top = all.ToList();

        onPreEnrichment?.Invoke(perType, errors, top.Count);

        // Apply the local ASN type filter before RIPE Stat calls.
        // ASNs confirmed by local hosting files always pass.
        // Other ASNs need an explicit hosting type. Missing or different types are rejected.
        // The local as.json and bgp.tools type map does not need an outage fallback.
        // when the map is absent entirely, EnrichWithPrefixesAsync applies balanced filtering.
        if (excludeCdn && _asnTypes != null)
        {
            int before = top.Count;
            top = [.. top.Where(c =>
            {
                var t = LookupAsnType(c.Asn);
                if (t is "hosting" or "cloud") return true;
                // The ipcat, cloud, and server IP allowlists only rescue unknown types.
                // ranges in the datasets go stale and change hands
                // (Blizzard inherited PEER 1's ipcat entry), so an explicit
                // non-hosting verdict always outweighs the whitelist.
                return t == null && (localHostingWhitelist?.Contains(c.Asn) ?? false);
            })];
            onStatus?.Invoke($"ASN type (local): {before} → {top.Count} candidates after the hosting filter");
        }

        // The local type filter reduces RIPE Stat calls but does not provide a
        // substitute for the full check below (it has no CAIDA/NSP/size-threshold logic), so
        // filterHostingOnly always runs regardless of whether the pre-filter ran. Passing whitelist
        // membership through both stages let large NSP carriers with no positive hosting signal
        // (Hurricane Electric, Colt, Equinix, M247, DataBank) slip through this path only.
        return await EnrichWithPrefixesAsync(top, ct,
            filterHostingOnly: excludeCdn,
            localHostingWhitelist: localHostingWhitelist,
            strictContentFilter: false);
    }

    // Regional search: finds networks present at IXPs matching the region name.
    public async Task<IReadOnlyList<ProviderCandidate>> FindByRegionAsync(
        string region, string[]? infoTypes = null, bool excludeCdn = false,
        bool excludeAi = false, bool aiOnly = false,
        HashSet<uint>? localHostingWhitelist = null, CancellationToken ct = default)
    {
        using var phaseBudget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        phaseBudget.CancelAfter(TimeSpan.FromSeconds(4));
        var phaseToken = phaseBudget.Token;

        List<int> ixIds;
        try
        {
            using var ixReq = PdbRequest(
                $"{PeeringDbBase}/ix?name_search={Uri.EscapeDataString(region)}&status=ok");
            using var ixResp = await peeringDbHttp.SendAsync(ixReq, phaseToken);
            if (!ixResp.IsSuccessStatusCode) return [];
            var ixJson = await ixResp.Content.ReadAsStringAsync(phaseToken);
            using var ixDoc = JsonDocument.Parse(ixJson);
            ixIds = ixDoc.RootElement
                .GetProperty("data")
                .EnumerateArray()
                .Select(e => e.GetProperty("id").GetInt32())
                .ToList();
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return []; }
        catch { return []; }

        if (ixIds.Count == 0) return [];

        var netIdSet = new System.Collections.Concurrent.ConcurrentDictionary<int, byte>();
        try
        {
            await Parallel.ForEachAsync(ixIds,
                new ParallelOptions { MaxDegreeOfParallelism = 10, CancellationToken = phaseToken },
                async (ixId, innerCt) =>
                {
                    try
                    {
                        using var lanReq = PdbRequest($"{PeeringDbBase}/netixlan?ix_id={ixId}&status=ok");
                        using var lanResp = await peeringDbHttp.SendAsync(lanReq, innerCt);
                        if (!lanResp.IsSuccessStatusCode) return;
                        var lanJson = await lanResp.Content.ReadAsStringAsync(innerCt);
                        using var lanDoc = JsonDocument.Parse(lanJson);
                        foreach (var entry in lanDoc.RootElement.GetProperty("data").EnumerateArray())
                            if (entry.TryGetProperty("net_id", out var netIdEl))
                                netIdSet.TryAdd(netIdEl.GetInt32(), 0);
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { }
                });
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { }

        var slim = new System.Collections.Concurrent.ConcurrentBag<ProviderCandidate>();
        try
        {
            await Parallel.ForEachAsync(netIdSet.Keys,
                new ParallelOptions { MaxDegreeOfParallelism = 10, CancellationToken = phaseToken },
                async (netId, innerCt) =>
                {
                    try
                    {
                        using var netReq = PdbRequest($"{PeeringDbBase}/net/{netId}");
                        using var netResp = await peeringDbHttp.SendAsync(netReq, innerCt);
                        if (!netResp.IsSuccessStatusCode) return;
                        var netJson = await netResp.Content.ReadAsStringAsync(innerCt);
                        using var netDoc = JsonDocument.Parse(netJson);
                        var arr = netDoc.RootElement.GetProperty("data");
                        if (arr.GetArrayLength() == 0) return;
                        var net = arr[0];
                        var candidate = ParseNetwork(net);
                        if (candidate != null) slim.Add(candidate);
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { }
                });
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { }

        var candidates = slim.AsEnumerable();
        if (infoTypes != null)
            candidates = candidates.Where(c =>
                infoTypes.Contains(c.InfoType, StringComparer.OrdinalIgnoreCase));
        if (excludeCdn)  candidates = candidates.Where(c => !IsCdnProvider(c));
        if (excludeAi)   candidates = candidates.Where(c => !IsAiProvider(c));
        if (aiOnly)      candidates = candidates.Where(c => IsAiProvider(c));

        var filtered = candidates.ToArray();
        var localPrefixes = BuildLocalPrefixFallback(filtered);
        if (phaseToken.IsCancellationRequested)
        {
            if (localPrefixes == null) return [];
            var localCandidates = filtered
                .Where(candidate => localPrefixes.ContainsKey(candidate.Asn))
                .ToArray();
            return await EnrichWithPrefixesAsync(localCandidates, ct,
                filterHostingOnly: excludeCdn,
                localHostingWhitelist: localHostingWhitelist,
                localPrefixFallback: localPrefixes);
        }

        try
        {
            return await EnrichWithPrefixesAsync(filtered, phaseToken,
                filterHostingOnly: excludeCdn,
                localHostingWhitelist: localHostingWhitelist,
                localPrefixFallback: localPrefixes);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException)
        {
            if (localPrefixes == null) return [];
            var localCandidates = filtered
                .Where(candidate => localPrefixes.ContainsKey(candidate.Asn))
                .ToArray();
            return await EnrichWithPrefixesAsync(localCandidates, ct,
                filterHostingOnly: excludeCdn,
                localHostingWhitelist: localHostingWhitelist,
                localPrefixFallback: localPrefixes);
        }
    }

    private static readonly TimeSpan PeeringDbCacheTtl = TimeSpan.FromHours(8);

    // Allowlisted info_type values protect PeeringDB URLs and cache paths.
    private static readonly HashSet<string> _allowedPeeringDbInfoTypes =
        new(StringComparer.OrdinalIgnoreCase) { "Content", "NSP", "Enterprise", "Hosting" };

    private string? PeeringDbCachePath(string infoType)
    {
        if (string.IsNullOrEmpty(_cacheDir)) return null;
        // Allowlist-only sanitization: only valid info_types reach this method,
        // but also strip path-separator characters defensively.
        var safeType = infoType.ToLowerInvariant()
            .Replace("/", "-").Replace(" ", "-")
            .Replace("\\", "").Replace("..", "");
        return Path.Combine(_cacheDir, $"peeringdb-{safeType}.json");
    }

    private async Task<IReadOnlyList<ProviderCandidate>?> TryLoadPeeringDbCacheAsync(
        string infoType, CancellationToken ct, bool allowStale = false)
    {
        if (_cacheDir == null) return null;
        var path = PeeringDbCachePath(infoType);
        if (path == null || !File.Exists(path)) return null;
        try
        {
            if (!_peeringDbMemoryCache.TryGetValue(path, out var cache))
            {
                await using var fs = File.OpenRead(path);
                cache = await JsonSerializer.DeserializeAsync<PeeringDbCacheFile>(
                    fs, cancellationToken: ct);
                if (cache != null)
                    _peeringDbMemoryCache[path] = cache;
            }
            if (cache?.Candidates == null) return null;
            if (!allowStale && DateTimeOffset.UtcNow - cache.FetchedAt > PeeringDbCacheTtl)
                return null;
            return cache.Candidates.Select(d =>
                new ProviderCandidate(d.Asn, d.Name, d.Country, d.Website, d.InfoType, d.PeeringCount, null, [])
            ).ToList();
        }
        catch { return null; }
    }

    private async Task SavePeeringDbCacheAsync(
        string infoType, IReadOnlyList<ProviderCandidate> candidates, CancellationToken ct)
    {
        if (_cacheDir == null) return;
        try
        {
            var cache = new PeeringDbCacheFile
            {
                FetchedAt  = DateTimeOffset.UtcNow,
                Candidates = candidates.Select(c => new PeeringDbCacheFile.CandidateDto
                {
                    Asn          = c.Asn,
                    Name         = c.Name,
                    Country      = c.Country,
                    Website      = c.Website,
                    InfoType     = c.InfoType,
                    PeeringCount = c.PeeringCount,
                }).ToList()
            };
            var cachePath = PeeringDbCachePath(infoType);
            if (cachePath == null) return;
            await using var fs = File.Create(cachePath);
            await JsonSerializer.SerializeAsync(fs, cache, cancellationToken: ct);
            _peeringDbMemoryCache[cachePath] = cache;
        }
        catch { }
    }

    private sealed class PeeringDbCacheFile
    {
        public DateTimeOffset     FetchedAt  { get; set; }
        public List<CandidateDto>? Candidates { get; set; }

        public sealed class CandidateDto
        {
            public uint    Asn          { get; set; }
            public string  Name         { get; set; } = "";
            public string? Country      { get; set; }
            public string? Website      { get; set; }
            public string? InfoType     { get; set; }
            public int?    PeeringCount { get; set; }
        }
    }

    // PeeringDB defaults to 250 records per page. Paginate with skip until all records are fetched.
    // Returns candidates and an error message when the first page fails.
    // Live PeeringDB pagination handles rate limits and timeouts through network I/O.
    // I/O orchestration. The record parsing (ParseNetwork) and cache round-trip are unit-tested;
    // the fetch/retry loop is integration-scope, so it is excluded from the unit-coverage metric.
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    private async Task<(IReadOnlyList<ProviderCandidate> Candidates, string? Error)> FetchNetsByTypeAsync(
        string infoType, CancellationToken ct, Action<string>? onStatus = null)
    {
        if (!_allowedPeeringDbInfoTypes.Contains(infoType))
            return ([], $"Rejected disallowed PeeringDB info_type: {infoType}");

        var cached = await TryLoadPeeringDbCacheAsync(infoType, ct);
        if (cached != null) return (cached, null);
        var stale = await TryLoadPeeringDbCacheAsync(infoType, ct, allowStale: true);

        const int pageSize    = 500;
        const int maxPages    = 20;
        const int maxAttempts = 1;
        using var phaseBudget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        phaseBudget.CancelAfter(TimeSpan.FromSeconds(3));
        var phaseToken = phaseBudget.Token;
        var all       = new List<ProviderCandidate>();
        int skip      = 0;
        int pageCount = 0;
        while (pageCount < maxPages)
        {
            pageCount++;
            string? lastErr = null;
            HttpResponseMessage? resp = null;

            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                try
                {
                    var url = $"{PeeringDbBase}/net?info_type={infoType}&status=ok&limit={pageSize}&skip={skip}";
                    using var req = PdbRequest(url);
                    resp = await peeringDbHttp.SendAsync(req, phaseToken);

                    if (resp.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                    {
                        resp.Dispose(); resp = null;
                        lastErr = $"PeeringDB rate limit for info_type={infoType}";
                        break;
                    }

                    lastErr = null;
                    break; // A successful request ends the retry loop.
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (OperationCanceledException)
                {
                    lastErr = $"PeeringDB request timed out for info_type={infoType}";
                    if (attempt < maxAttempts)
                        await Task.Delay(TimeSpan.FromSeconds(attempt * 5), phaseToken);
                }
                catch (Exception ex)
                {
                    lastErr = $"PeeringDB fetch error for info_type={infoType}: {ex.Message}";
                    if (attempt < maxAttempts)
                        await Task.Delay(TimeSpan.FromSeconds(attempt * 3), phaseToken);
                }
            }

            if (lastErr != null)
                return (stale ?? all, pageCount == 1 ? lastErr : null);

            if (resp == null)
                return (stale ?? all, pageCount == 1 ? $"PeeringDB: rate limit for info_type={infoType} — try again later" : null);

            using (resp)
            {
                if (!resp.IsSuccessStatusCode)
                {
                    string err = $"PeeringDB returned HTTP {(int)resp.StatusCode} for info_type={infoType}";
                    return (stale ?? all, pageCount == 1 ? err : null);
                }

                string json;
                try
                {
                    json = await resp.Content.ReadAsStringAsync(phaseToken);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    return (stale ?? all, pageCount == 1
                        ? $"PeeringDB request timed out for info_type={infoType}"
                        : null);
                }
                using var doc = JsonDocument.Parse(json);
                var page = doc.RootElement.GetProperty("data").EnumerateArray()
                    .Select(n => ParseNetwork(n))
                    .Where(c => c != null)
                    .Select(c => c!)
                    .ToList();
                all.AddRange(page);
                if (page.Count < pageSize) break;
                skip += pageSize;
            }
        }
        await SavePeeringDbCacheAsync(infoType, all, ct);
        return (all, null);
    }

    // One rate limiter is shared by all RIPE Stat calls in this instance to avoid HTTP 429.
    // Each candidate acquires it once for prefixes and once for neighbors,
    // so the count must be at least twice MaxDegreeOfParallelism to avoid a potential deadlock.
    private readonly SemaphoreSlim _ripeSemaphore = new(20, 20);

    private async Task<IReadOnlyList<ProviderCandidate>> EnrichWithPrefixesAsync(
        IReadOnlyList<ProviderCandidate> candidates, CancellationToken ct,
        bool filterHostingOnly = false,
        HashSet<uint>? localHostingWhitelist = null,
        bool strictContentFilter = false,
        bool excludeAi = false,
        IReadOnlyDictionary<uint, IReadOnlyList<string>>? localPrefixFallback = null)
    {
        var withPrefixes = new System.Collections.Concurrent.ConcurrentBag<ProviderCandidate>();
        localPrefixFallback ??= BuildLocalPrefixFallback(candidates);

        // RIPE prefix and neighbor requests run together for each candidate.
        // ASN type checks use the local as.json and bgp.tools map without network access.
        await Parallel.ForEachAsync(candidates,
            new ParallelOptions { MaxDegreeOfParallelism = 10, CancellationToken = ct },
            async (candidate, innerCt) =>
            {
                IReadOnlyList<string>? localPrefixes = null;
                localPrefixFallback?.TryGetValue(candidate.Asn, out localPrefixes);
                var prefixTask    = FetchPrefixDataAsync(candidate.Asn, localPrefixes, innerCt);
                var neighbourTask = localPrefixes is { Count: > 0 }
                    ? Task.FromResult(ripeClient.TryGetCachedNeighbourCounts(
                        candidate.Asn, out var cachedCounts) ? cachedCounts : (0, 0))
                    : FetchNeighboursAsync(candidate.Asn, innerCt);

                await Task.WhenAll(prefixTask, neighbourTask);

                // Load prefix data first because the filter below needs the IP pool size.
                var (ipv4, ipv6)  = prefixTask.Result;
                var (upstream, _) = neighbourTask.Result;
                if (ipv4.Count == 0) return;
                long totalIps = Ipv4RangeMath.CountUniqueAddresses(ipv4);

                // Principled hosting filter (applied when --type server/vps/cloud is used):
                //
                // Entries from ipcat, cloud providers, and server IP files always pass.
                //
                // NSP transit and ISP networks require an ipapi.is hosting or cloud classification.
                //    Rationale: ISPs vastly outnumber hosting NSPs; false positives are common.
                //
                //  Content: lenient with targeted exclusions.
                // Pass hosting or cloud types from ipapi.is. Missing types pass with at least 1024 IPs.
                //    Reject: ipapi.is explicitly non-hosting (isp/cable/cdn/government/education),
                //            or null with <1024 IPs (micro-networks unlikely to be real VPS providers).
                //
                // This avoids maintaining hand-curated name/ASN exclusion lists while still
                // filtering TELE2 (isp), Disney (cdn), tiny junk networks, etc.
                // Hard block: non-hosting companies (Apple, Netflix, Meta) never appear in results.
                if (IsNonHostingProvider(candidate)) return;

                // Hard block: AI/GPU-only cloud providers (CoreWeave, Lambda, Crusoe, etc.) are
                // never included when --type excludes AI for server-related filters. This must
                // apply regardless of candidate origin (PeeringDB match, RIPE overview fallback,
                // or supplement paths like bgp.tools vpsh) since all of them funnel through here.
                if (excludeAi && IsAiProvider(candidate)) return;

                // Hard block: government bodies, research/education networks, IXPs and
                // undisclosed networks are never commercial hosting providers.
                if (candidate.InfoType?.ToLowerInvariant() is
                        "government" or "research/education" or "exchange point" or "not disclosed")
                    return;

                if (filterHostingOnly)
                {
                    // Hard block: CDN ASNs are never included regardless of whitelist.
                    if (IsCdnProvider(candidate)) return;

                    var asnType = LookupAsnType(candidate.Asn);

                    // Explicit non-hosting results are rejected before the allowlist check.
                    // range datasets go stale and ranges change hands (Blizzard inherited
                    // an ipcat PEER 1 range), so a known type always beats the whitelist.
                    if (asnType is "isp" or "cable" or "cdn" or "government" or
                                   "education" or "inactive" or "business" or "personal")
                        return;

                    // asnType is null here (or "hosting"/"cloud" which always passes).
                    if (asnType is not ("hosting" or "cloud"))
                    {
                        bool inWhitelist = localHostingWhitelist?.Contains(candidate.Asn) ?? false;
                        var caidaCls = _caida?.TryGetValue(candidate.Asn, out var cls) == true ? cls : null;
                        if (!ShouldIncludeUnverifiedHostingCandidate(
                                candidate.InfoType, caidaCls, inWhitelist, totalIps, strictContentFilter))
                            return;
                    }
                }
                withPrefixes.Add(candidate with {
                    Prefixes        = [.. ipv4],
                    TotalIpCount    = totalIps,
                    HasIPv6         = ipv6.Count > 0,
                    IPv6PrefixCount = ipv6.Count,
                    UpstreamCount   = upstream,
                });
            });

        return [.. withPrefixes];
    }

    private async Task<(IReadOnlyList<string> IPv4, IReadOnlyList<string> IPv6)> FetchPrefixDataAsync(
        uint asn,
        IReadOnlyList<string>? localPrefixes,
        CancellationToken ct)
    {
        if (ripeClient.TryGetCachedPrefixes(asn, out var cachedIpv4, out var cachedIpv6))
            return (cachedIpv4, cachedIpv6);
        if (localPrefixes is { Count: > 0 })
            return (localPrefixes, []);

        IReadOnlyList<string> ipv4 = [];
        IReadOnlyList<string> ipv6 = [];
        bool ripeOk   = false;
        bool acquired = false;
        try
        {
            await _ripeSemaphore.WaitAsync(ct);
            acquired = true;
            // The client fails soft on its own (Ok=false); only cancellation escapes it.
            (ripeOk, ipv4, ipv6) = await ripeClient.GetAllPrefixesAsync(asn, ct);
        }
        finally { if (acquired) _ripeSemaphore.Release(); }

        // BGPView fallback: RIPE Stat and local data returned no IPv4 prefixes for this ASN.
        // The fallback is limited to about 42 requests per minute and only runs for missing ASNs.
        // Preserves any IPv6 data already returned by RIPE Stat.
        // Known-empty ASNs with a pfx0 marker skip the throttled call during the cache TTL.
        // otherwise ~100 serialized fallback requests add minutes to every run.
        if (ipv4.Count == 0 && _bgpView != null && !ripeClient.IsKnownEmpty(asn))
        {
            var (bgpOk, bgpIpv4, bgpIpv6) = await _bgpView.GetPrefixesAsync(asn, ct);
            ipv4 = bgpIpv4;
            if (ipv6.Count == 0) ipv6 = bgpIpv6;

            if (ipv4.Count > 0) ripeClient.CachePrefixes(asn, ipv4, ipv6); // Fallback data uses the same pfx_ key.
            // WR-01: the full 24h marker only on CONFIRMED emptiness, where both sources
            // successfully answered "no prefixes". A double transient failure (general network
            // degradation, a double rate-limit) no longer marks a healthy ASN as empty for 24h.
            // Unconfirmed emptiness gets a SHORT marker (1h): without it every
            // run went back to a serialized BGPView (1.4s/ASN); during a system-wide
            // BGPView outage that is minutes on EVERY run instead of one hourly window.
            else if (ripeOk && bgpOk) ripeClient.MarkEmpty(asn);
            else                      ripeClient.MarkEmpty(asn, TimeSpan.FromHours(1));
        }

        return (ipv4, ipv6);
    }

    private IReadOnlyDictionary<uint, IReadOnlyList<string>>? BuildLocalPrefixFallback(
        IReadOnlyList<ProviderCandidate> candidates)
        => BuildLocalPrefixFallback(candidates.Select(candidate => candidate.Asn));

    private IReadOnlyDictionary<uint, IReadOnlyList<string>>? BuildLocalPrefixFallback(
        IEnumerable<uint> asns)
    {
        if (_localIp2AsnRecords == null)
            return null;

        var wanted = asns.ToHashSet();
        if (wanted.Count == 0) return null;
        var prefixes = new Dictionary<uint, List<string>>();
        foreach (var record in _localIp2AsnRecords)
        {
            if (record.Asn == 0 || !wanted.Contains(record.Asn)) continue;
            if (!prefixes.TryGetValue(record.Asn, out var list))
                prefixes[record.Asn] = list = [];
            list.Add(IpConverter.ToCidr(record.StartIp, record.EndIp));
        }
        return prefixes.ToDictionary(
            pair => pair.Key,
            pair => (IReadOnlyList<string>)pair.Value);
    }

    private IReadOnlyDictionary<uint, string>? BuildLocalNameFallback(IEnumerable<uint> asns)
    {
        if (_localIp2AsnRecords == null)
            return null;

        var wanted = asns.ToHashSet();
        if (wanted.Count == 0) return null;
        var counts = new Dictionary<uint, Dictionary<string, int>>();
        foreach (var record in _localIp2AsnRecords)
        {
            if (record.Asn == 0 || !wanted.Contains(record.Asn)
                || string.IsNullOrWhiteSpace(record.Description))
                continue;
            if (!counts.TryGetValue(record.Asn, out var byName))
                counts[record.Asn] = byName = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            string name = record.Description.Trim();
            byName[name] = byName.GetValueOrDefault(name) + 1;
        }
        return counts.ToDictionary(
            pair => pair.Key,
            pair => pair.Value
                .OrderByDescending(item => item.Value)
                .ThenBy(item => item.Key.Length)
                .ThenBy(item => item.Key, StringComparer.OrdinalIgnoreCase)
                .First().Key);
    }

    private async Task<(int Upstream, int Downstream)> FetchNeighboursAsync(
        uint asn, CancellationToken ct)
    {
        bool acquired = false;
        try
        {
            await _ripeSemaphore.WaitAsync(ct);
            acquired = true;
            // The client fails soft on its own (0, 0); only cancellation escapes it.
            return await ripeClient.GetNeighbourCountsAsync(asn, ct);
        }
        finally { if (acquired) _ripeSemaphore.Release(); }
    }

    public static long CountIpsInCidr(string cidr)
        => Ipv4RangeMath.CountAddresses(cidr);

    // Stubs for ASNs from asnList that produced no candidate in the enrichment loop: only those
    // present in nameFallback (core names); non-core entries cannot reach here. Prefixes are filled in by
    // localPrefixFallback in EnrichWithPrefixesAsync. Guarantees a core member is not lost
    // due to a PeeringDB 429/error. A pure function, tested in isolation.
    public static IReadOnlyList<ProviderCandidate> BackfillNameStubs(
        IReadOnlyList<(uint Asn, int Coverage)> asnList,
        IReadOnlySet<uint> existingAsns,
        IReadOnlyDictionary<uint, string>? nameFallback)
    {
        if (nameFallback == null) return [];
        return [.. asnList
            .Where(e => !existingAsns.Contains(e.Asn) && nameFallback.ContainsKey(e.Asn))
            .Select(e => new ProviderCandidate(e.Asn, nameFallback[e.Asn], null, null, null, null, null, [])
                with { CoverageCount = e.Coverage })];
    }

    // IP-list mode: find providers for a pre-computed list of (ASN, coverageCount) pairs.
    // Unlike FindGlobalAsync, this method resolves IPs to ASNs before querying PeeringDB.
    // When infoTypes is non-null (e.g. --type vps), only matching PeeringDB entries pass.
    // ASNs not in PeeringDB are included as fallback only when no type filter is active.
    public async Task<IReadOnlyList<ProviderCandidate>> FindByAsnListAsync(
        IReadOnlyList<(uint Asn, int Coverage)> asnList,
        string[]? infoTypes = null,
        bool excludeCdn = false,
        bool excludeAi = false,
        HashSet<uint>? localHostingWhitelist = null,
        Action<string>? onError = null,
        Action<int, int, int>? onDiagnostic = null, // (inputCount, afterIpapiFilter, metadataResolved)
        IReadOnlyDictionary<uint, IReadOnlyList<string>>? localPrefixFallback = null,
        IReadOnlyDictionary<uint, string>? nameFallback = null,
        bool aiOnly = false,
        CancellationToken ct = default)
    {
        // CDN exclusion removes known CDN ASNs even when they appear in the local allowlist.
        if (excludeCdn && asnList.Any(a => _excl.KnownCdnAsns.Contains(a.Asn)))
            asnList = asnList.Where(a => !_excl.KnownCdnAsns.Contains(a.Asn)).ToList();

        bool hasTypeFilter = infoTypes is { Length: > 0 };

        // Apply the local ASN type filter before PeeringDB when a type filter is active.
        // This prevents burning the PeeringDB rate limit on ISPs that EnrichWithPrefixesAsync
        // would eliminate anyway. ISPs resolve to "isp"/"cable" and are dropped here cheaply.
        // Unknown types (null) get benefit of the doubt and proceed to PeeringDB.
        var enrichList = asnList;
        if (hasTypeFilter && _asnTypes != null)
        {
            enrichList = [.. asnList
                .Where(entry => LookupAsnType(entry.Asn) is null or "hosting" or "cloud")
                .OrderByDescending(a => a.Coverage)];
        }

        localPrefixFallback ??= BuildLocalPrefixFallback(enrichList.Select(entry => entry.Asn));
        nameFallback ??= BuildLocalNameFallback(enrichList.Select(entry => entry.Asn));

        var candidates = new System.Collections.Concurrent.ConcurrentBag<ProviderCandidate>();
        var excludedAsns = new System.Collections.Concurrent.ConcurrentDictionary<uint, byte>();
        int rateLimitReported = 0;
        int metadataLookupsCompleted = 0;

        bool MatchesMetadataFilters(ProviderCandidate candidate)
        {
            if (hasTypeFilter && !infoTypes!.Contains(
                    candidate.InfoType ?? "", StringComparer.OrdinalIgnoreCase))
                return false;
            if (excludeCdn && IsCdnProvider(candidate)) return false;
            if (excludeAi && IsAiProvider(candidate)) return false;
            if (aiOnly && !IsAiProvider(candidate)) return false;
            return true;
        }

        // Cap PeeringDB requests to avoid rate limiting.
        // Trusted ASNs from local hosting files do not need a cap.
        // A reduction above 30 percent means the local filter already limited the input.
        // Unfiltered user input is capped at 50 ASNs as a safety measure.
        bool ipapiFiltered = enrichList.Count < asnList.Count * 0.7;
        bool trustedAsns   = localHostingWhitelist != null;
        int peeringDbCap   = (ipapiFiltered || trustedAsns) ? enrichList.Count : 50;
        var cacheHandledAsns = new HashSet<uint>();

        string[] bulkCacheTypes = hasTypeFilter
            ? [.. infoTypes!
                .Where(_allowedPeeringDbInfoTypes.Contains)
                .Distinct(StringComparer.OrdinalIgnoreCase)]
            : ["Content", "NSP", "Enterprise"];
        var bulkCacheResults = await Task.WhenAll(bulkCacheTypes.Select(
            type => TryLoadPeeringDbCacheAsync(type, ct, allowStale: true)));
        bool bulkCacheIsComplete = bulkCacheTypes.Length > 0
            && bulkCacheResults.All(result => result != null);
        var bulkMetadataByAsn = bulkCacheResults
            .Where(result => result != null)
            .SelectMany(result => result!)
            .GroupBy(candidate => candidate.Asn)
            .ToDictionary(group => group.Key, group => group.First());

        bool TryHandleBulkCache((uint Asn, int Coverage) entry)
        {
            if (bulkMetadataByAsn.TryGetValue(entry.Asn, out var bulkCandidate))
            {
                cacheHandledAsns.Add(entry.Asn);
                Interlocked.Increment(ref metadataLookupsCompleted);
                if (MatchesMetadataFilters(bulkCandidate))
                    candidates.Add(bulkCandidate with { CoverageCount = entry.Coverage });
                else
                    excludedAsns.TryAdd(entry.Asn, 0);
                return true;
            }

            if (!bulkCacheIsComplete)
                return false;

            cacheHandledAsns.Add(entry.Asn);
            Interlocked.Increment(ref metadataLookupsCompleted);
            if (!hasTypeFilter && !aiOnly
                && nameFallback != null
                && nameFallback.TryGetValue(entry.Asn, out var fallbackName))
            {
                candidates.Add(new ProviderCandidate(
                    entry.Asn, fallbackName, null, null, null, null, null, [])
                    with { CoverageCount = entry.Coverage });
            }
            else
            {
                excludedAsns.TryAdd(entry.Asn, 0);
            }
            return true;
        }

        // Read every cached record before starting the bounded network queue.
        // Slow cache misses cannot hide complete metadata that is already on disk.
        foreach (var entry in enrichList)
        {
            if (_ripeCache == null
                || !_ripeCache.TryGet($"pdb_{entry.Asn}", out var cachedNet))
            {
                TryHandleBulkCache(entry);
                continue;
            }
            var record = DeserializePdbNetOrNull(cachedNet!);
            if (record == null)
            {
                TryHandleBulkCache(entry);
                continue;
            }

            cacheHandledAsns.Add(entry.Asn);
            Interlocked.Increment(ref metadataLookupsCompleted);
            ProviderCandidate? cachedCandidate = record.Found && record.Name != null
                ? new ProviderCandidate(
                    entry.Asn, record.Name, record.Country, record.Website,
                    record.InfoType, record.PeeringCount, null, [])
                : null;

            if (cachedCandidate != null)
            {
                if (MatchesMetadataFilters(cachedCandidate))
                    candidates.Add(cachedCandidate with { CoverageCount = entry.Coverage });
                else
                    excludedAsns.TryAdd(entry.Asn, 0);
                continue;
            }

            if (!hasTypeFilter && !aiOnly
                && nameFallback != null
                && nameFallback.TryGetValue(entry.Asn, out var fallbackName))
            {
                candidates.Add(new ProviderCandidate(
                    entry.Asn, fallbackName, null, null, null, null, null, [])
                    with { CoverageCount = entry.Coverage });
            }
            else
            {
                excludedAsns.TryAdd(entry.Asn, 0);
            }
        }

        var peeringDbList  = new List<(uint Asn, int Coverage)>();
        peeringDbList.AddRange(enrichList
            .Where(entry => !cacheHandledAsns.Contains(entry.Asn))
            .Take(peeringDbCap));

        using var batchBudget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        batchBudget.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            await Parallel.ForEachAsync(peeringDbList,
            new ParallelOptions { MaxDegreeOfParallelism = 6, CancellationToken = batchBudget.Token },
            async (entry, innerCt) =>
            {
                ProviderCandidate? candidate = null;
                bool foundInPeeringDb = false;

                // Entries reaching this loop had no readable pdb_ cache record moments ago
                // (the pre-loop pass consumed every hit), so the lookup goes straight to the
                // network. The RAW record is cached pre-filter so per-call type/CDN filters
                // below apply, and the next run's pre-loop pass serves it from the cache.
                try
                {
                    using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(innerCt);
                    reqCts.CancelAfter(TimeSpan.FromSeconds(2));
                    using var req = PdbRequest($"{PeeringDbBase}/net?asn={entry.Asn}&status=ok");
                    using var resp = await peeringDbHttp.SendAsync(req, reqCts.Token);

                    if (resp.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                    {
                        // Report the error once because parallel requests receive the same 429 response.
                        if (Interlocked.Exchange(ref rateLimitReported, 1) == 0)
                            onError?.Invoke(
                                "PeeringDB rate limit hit (HTTP 429) — enrichment incomplete, try again later.");
                        return;
                    }

                    if (!resp.IsSuccessStatusCode) return;

                    var netJson = await resp.Content.ReadAsStringAsync(innerCt);
                    using var doc = JsonDocument.Parse(netJson);
                    var arr = doc.RootElement.GetProperty("data");
                    if (arr.GetArrayLength() > 0)
                    {
                        foundInPeeringDb = true;
                        candidate = ParseNetwork(arr[0], requireInfoType: false);
                    }
                    Interlocked.Increment(ref metadataLookupsCompleted);
                    // Cache only successful lookups, including confirmed missing records.
                    // errors/timeouts above returned early or fall to catch.
                    _ripeCache?.Set($"pdb_{entry.Asn}",
                        SerializePdbNet(candidate, foundInPeeringDb), PeeringDbCacheTtl);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch { }

                // Apply request filters to both fresh and cached records.
                if (candidate != null && !MatchesMetadataFilters(candidate))
                {
                    excludedAsns.TryAdd(entry.Asn, 0);
                    candidate = null;
                }

                // Fallback: only when PeeringDB genuinely has NO record for this ASN.
                // Do not use the fallback after a CDN or type filter explicitly excludes an ASN.
                // that would bypass the exclusion via the RIPE Stat path (Cloudflare bug).
                if (candidate == null && !foundInPeeringDb && !hasTypeFilter && !aiOnly)
                {
                    if (nameFallback != null
                        && nameFallback.TryGetValue(entry.Asn, out var fallbackName))
                    {
                        candidate = new ProviderCandidate(
                            entry.Asn, fallbackName, null, null, null, null, null, []);
                    }
                    else
                    {
                        try
                        {
                            var overview = await ripeClient.GetAsnOverviewAsync(entry.Asn, innerCt);
                            if (overview != null)
                                candidate = new ProviderCandidate(
                                    entry.Asn, overview.Holder ?? $"AS{entry.Asn}",
                                    null, null, null, null, null, []);
                        }
                        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                        catch { }
                    }
                }

                if (candidate != null)
                    candidates.Add(candidate with { CoverageCount = entry.Coverage });
            });
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
        }

        // Backfill with core names: any ASN that produced no candidate in the loop (PeeringDB 429/error/
        // early return/no record, and RIPE overview is silent) is added as a stub with the core name.
        // Prefixes are filled in by localPrefixFallback in EnrichWithPrefixesAsync, so a core member is not lost.
        if (!hasTypeFilter && !aiOnly)
        {
            var existingOrExcluded = new HashSet<uint>(candidates.Select(candidate => candidate.Asn));
            existingOrExcluded.UnionWith(excludedAsns.Keys);
            foreach (var stub in BackfillNameStubs(
                         enrichList, existingOrExcluded, nameFallback))
                candidates.Add(stub);
        }

        onDiagnostic?.Invoke(asnList.Count, enrichList.Count, metadataLookupsCompleted);

        return await EnrichWithPrefixesAsync([.. candidates], ct,
            filterHostingOnly: excludeCdn, localHostingWhitelist: localHostingWhitelist,
            excludeAi: excludeAi, localPrefixFallback: localPrefixFallback);
    }

    // Wrapper for pdb_{asn} cache entries: Found=false means "PeeringDB has no record"
    // (negative caching); Found=true with null Name means "record exists but unparseable"
    // (suppresses the RIPE overview fallback, same as a live unparseable response).
    internal record PdbNetCacheData(
        [property: System.Text.Json.Serialization.JsonPropertyName("f")] bool    Found,
        [property: System.Text.Json.Serialization.JsonPropertyName("n")] string? Name,
        [property: System.Text.Json.Serialization.JsonPropertyName("c")] string? Country,
        [property: System.Text.Json.Serialization.JsonPropertyName("w")] string? Website,
        [property: System.Text.Json.Serialization.JsonPropertyName("t")] string? InfoType,
        [property: System.Text.Json.Serialization.JsonPropertyName("p")] int?    PeeringCount);

    internal static string SerializePdbNet(ProviderCandidate? c, bool found)
        => JsonSerializer.Serialize(new PdbNetCacheData(
            found, c?.Name, c?.Country, c?.Website, c?.InfoType, c?.PeeringCount));

    // Corrupt JSON is treated as "no cached data" (swallow-and-fallback convention).
    internal static PdbNetCacheData? DeserializePdbNetOrNull(string json)
    {
        try { return JsonSerializer.Deserialize<PdbNetCacheData>(json); }
        catch (JsonException) { return null; }
    }

    private static ProviderCandidate? ParseNetwork(JsonElement net, bool requireInfoType = true)
    {
        // PeeringDB uses "asn" field in /api/net responses.
        if (!net.TryGetProperty("asn", out var asnEl)) return null;
        var asnRaw = asnEl.GetInt64();
        if (asnRaw <= 0 || asnRaw > uint.MaxValue) return null;
        var asn = (uint)asnRaw;
        var infoType = net.TryGetProperty("info_type", out var it) ? it.GetString() : null;
        if (requireInfoType &&
            infoType?.ToLowerInvariant() is not ("hosting" or "content" or "nsp" or "enterprise")) return null;
        var name     = net.TryGetProperty("name",     out var nm)  ? nm.GetString()  ?? $"AS{asn}" : $"AS{asn}";
        var website  = net.TryGetProperty("website",  out var wb)  ? wb.GetString()  : null;
        var country  = net.TryGetProperty("country",  out var co)  ? co.GetString()  : null;
        var ixCount  = net.TryGetProperty("ix_count", out var ixc) ? (int?)ixc.GetInt32() : null;
        return new ProviderCandidate(asn, name, country, website, infoType, ixCount, null, []);
    }
}
