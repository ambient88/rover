using System.Text.Json;
using SubnetSearch.Classification;
using SubnetSearch.Core.Models.Network;
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
    // Локальная карта asn → тип ("hosting"/"isp"/"business"/"cdn"/…), собранная
    // AsnTypeResolver'ом из as.json + bgp.tools tags. Заменяет сетевые запросы к ipapi.is:
    // ноль квоты, работает офлайн, недоступность источника невозможна.
    IReadOnlyDictionary<uint, string>? asnTypes = null,
    AsnExclusions?  exclusions            = null,
    BgpViewClient?  bgpView               = null,
    string?         cacheDir              = null,
    IReadOnlyDictionary<uint, string>? caidaClassifications = null,
    RipeStatCache?  ripeCache             = null,
    // The PeeringDB key is attached to individual requests.
    string?         peeringDbKey          = null)
{
    private readonly AsnExclusions  _excl      = exclusions ?? AsnExclusions.Default;
    private readonly BgpViewClient? _bgpView   = bgpView;
    private readonly string?        _cacheDir  = cacheDir;
    private readonly RipeStatCache? _ripeCache = ripeCache;
    private readonly IReadOnlyDictionary<uint, string>? _caida = caidaClassifications;
    private readonly IReadOnlyDictionary<uint, string>? _asnTypes = asnTypes;
    private readonly string? _pdbKey = PeeringDbAuth.Sanitize(peeringDbKey);

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
    // Returns null for unrecognized non-null input — caller should treat as invalid.
    //
    // NOTE: PeeringDB's info_type="Hosting" is empty — no providers use it.
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

    // Allowlist-членство для server-типов (заменяет ApplyTaxonomyFilter): кандидат остаётся,
    // ТОЛЬКО если он в курируемом ядре по типу (pure allowlist — авто-гейт убран).
    // Для не-server typeFilter (cdn/nsp/ai/null-как-«не сервер») — возвращает вход без изменений.
    public static IReadOnlyList<ProviderCandidate> ApplyServerAllowlist(
        IReadOnlyList<ProviderCandidate> candidates,
        string? typeFilter,
        ServerProviders serverProviders)
    {
        if (!IsServerTypeFilter(typeFilter)) return candidates;
        // typeFilter приходит сырым (регистр не нормализован выше). hosting — документированный
        // алиас server; приводим к нижнему регистру и сворачиваем hosting→server для membership.
        var t = typeFilter!.ToLowerInvariant();
        if (t == "hosting") t = "server";
        return [.. candidates.Where(c => serverProviders.IsAllowed(c.Asn, t))];
    }

    // server-семейство фильтров, к которым применяется allowlist (hosting — алиас server).
    public static bool IsServerTypeFilter(string? typeFilter) =>
        typeFilter?.ToLowerInvariant() is "server" or "hosting" or "vps" or "dedicated" or "cloud";

    // core-first источник кандидатов применяется только для global server-типа без --from:
    // тогда кандидаты берутся из ядра, а не из широкого PeeringDB-pull.
    public static bool UseCoreFirstSource(string? typeFilter, string? region, bool hasFromList) =>
        IsServerTypeFilter(typeFilter) && string.IsNullOrWhiteSpace(region) && !hasFromList;

    // Оставляет только ASN, чьё множество стран (из ip2asn) пересекается с запрошенными кодами.
    // Пустой countryCodes → вернуть вход как есть (без фильтра). Полностью локально, без сети.
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
    // (no I/O — fully testable). CAIDA and NSP checks apply REGARDLESS of the local IP-range
    // whitelist (ipcat/cloud-provider/server-ip datasets flag "this address block sits in a
    // datacenter", not "this org sells retail VPS/dedicated servers" — a wholesale transit
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
        // NOTE: "Hosting" is intentionally omitted — PeeringDB has no networks with that type.
        // Requests are sequential to avoid triggering PeeringDB rate limits from parallel bursts.
        var types   = infoTypes ?? ["Content", "NSP"];
        var fetches = new List<(IReadOnlyList<ProviderCandidate> Candidates, string? Error)>();
        foreach (var t in types)
            fetches.Add(await FetchNetsByTypeAsync(t, ct, onStatus));

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

        // NOTE: PeeringDB bulk /api/net does not return a 'country' field, so client-side
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

        // When hosting filter is active, pre-filter by local ASN type BEFORE RIPE Stat calls.
        // Whitelist ASNs (confirmed local hosting files) → always pass.
        // Non-whitelist ASNs → must have explicit "hosting" type; null/other → rejected.
        // The type map is local (as.json + bgp.tools tags), so there is no outage fallback:
        // when the map is absent entirely, EnrichWithPrefixesAsync applies balanced filtering.
        if (excludeCdn && _asnTypes != null)
        {
            int before = top.Count;
            top = [.. top.Where(c =>
            {
                var t = LookupAsnType(c.Asn);
                if (t is "hosting" or "cloud") return true;
                // Whitelist (ipcat/cloud/server-ips) спасает ТОЛЬКО неизвестных:
                // диапазоны в датасетах устаревают и переходят из рук в руки
                // (Blizzard унаследовал ipcat-запись PEER 1), поэтому явный
                // не-hosting вердикт всегда сильнее whitelist.
                return t == null && (localHostingWhitelist?.Contains(c.Asn) ?? false);
            })];
            onStatus?.Invoke($"ASN type (local): {before} → {top.Count} candidates after the hosting filter");
        }

        // The local-type pre-filter above is cheap triage to cut RIPE Stat calls; it is NOT a
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
        List<int> ixIds;
        try
        {
            using var ixReq = PdbRequest(
                $"{PeeringDbBase}/ix?name_search={Uri.EscapeDataString(region)}&status=ok");
            using var ixResp = await peeringDbHttp.SendAsync(ixReq, ct);
            if (!ixResp.IsSuccessStatusCode) return [];
            var ixJson = await ixResp.Content.ReadAsStringAsync(ct);
            using var ixDoc = JsonDocument.Parse(ixJson);
            ixIds = ixDoc.RootElement
                .GetProperty("data")
                .EnumerateArray()
                .Select(e => e.GetProperty("id").GetInt32())
                .ToList();
        }
        catch (OperationCanceledException) { throw; }
        catch { return []; }

        if (ixIds.Count == 0) return [];

        var netIdSet = new HashSet<int>();
        foreach (var ixId in ixIds)
        {
            try
            {
                using var lanReq = PdbRequest($"{PeeringDbBase}/netixlan?ix_id={ixId}&status=ok");
                using var lanResp = await peeringDbHttp.SendAsync(lanReq, ct);
                if (!lanResp.IsSuccessStatusCode) continue;
                var lanJson = await lanResp.Content.ReadAsStringAsync(ct);
                using var lanDoc = JsonDocument.Parse(lanJson);
                foreach (var entry in lanDoc.RootElement.GetProperty("data").EnumerateArray())
                    if (entry.TryGetProperty("net_id", out var netIdEl))
                        netIdSet.Add(netIdEl.GetInt32());
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        var slim = new System.Collections.Concurrent.ConcurrentBag<ProviderCandidate>();
        await Parallel.ForEachAsync(netIdSet,
            new ParallelOptions { MaxDegreeOfParallelism = 10, CancellationToken = ct },
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

        var candidates = slim.AsEnumerable();
        if (infoTypes != null)
            candidates = candidates.Where(c =>
                infoTypes.Contains(c.InfoType, StringComparer.OrdinalIgnoreCase));
        if (excludeCdn)  candidates = candidates.Where(c => !IsCdnProvider(c));
        if (excludeAi)   candidates = candidates.Where(c => !IsAiProvider(c));
        if (aiOnly)      candidates = candidates.Where(c => IsAiProvider(c));

        return await EnrichWithPrefixesAsync([.. candidates], ct,
            filterHostingOnly: excludeCdn, localHostingWhitelist: localHostingWhitelist);
    }

    private static readonly TimeSpan PeeringDbCacheTtl = TimeSpan.FromHours(8);

    // Allowed info_type values for PeeringDB queries — guards URL construction and cache paths.
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
        string infoType, CancellationToken ct)
    {
        if (_cacheDir == null) return null;
        var path = PeeringDbCachePath(infoType);
        if (path == null || !File.Exists(path)) return null;
        try
        {
            await using var fs    = File.OpenRead(path);
            var cache = await JsonSerializer.DeserializeAsync<PeeringDbCacheFile>(fs, cancellationToken: ct);
            if (cache?.Candidates == null) return null;
            if (DateTimeOffset.UtcNow - cache.FetchedAt > PeeringDbCacheTtl) return null;
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
    // Returns (candidates, errorMessage) — error is non-null when the first page fails.
    // Live PeeringDB HTTP pagination with 429/timeout retry + rate-limit backoff — pure network
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

        const int pageSize    = 500;
        const int maxPages    = 20;
        const int maxAttempts = 3;
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
                    using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    reqCts.CancelAfter(TimeSpan.FromSeconds(8));

                    using var req = PdbRequest(url);
                    resp = await peeringDbHttp.SendAsync(req, reqCts.Token);

                    if (resp.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                    {
                        var retryAfter = resp.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(15);
                        int delayMs = (int)Math.Min(Math.Max(0.0, retryAfter.TotalMilliseconds), 30_000);
                        resp.Dispose(); resp = null;
                        if (delayMs > 5_000)
                            onStatus?.Invoke($"PeeringDB: rate limited — waiting {delayMs / 1000}s...");
                        await Task.Delay(delayMs, ct);
                        continue; // retry
                    }

                    lastErr = null;
                    break; // success — exit retry loop
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (OperationCanceledException)
                {
                    lastErr = $"PeeringDB request timed out for info_type={infoType}";
                    if (attempt < maxAttempts)
                        await Task.Delay(TimeSpan.FromSeconds(attempt * 5), ct);
                }
                catch (Exception ex)
                {
                    lastErr = $"PeeringDB fetch error for info_type={infoType}: {ex.Message}";
                    if (attempt < maxAttempts)
                        await Task.Delay(TimeSpan.FromSeconds(attempt * 3), ct);
                }
            }

            if (lastErr != null)
                return (all, pageCount == 1 ? lastErr : null);

            if (resp == null)
                return (all, pageCount == 1 ? $"PeeringDB: rate limit for info_type={infoType} — try again later" : null);

            using (resp)
            {
                if (!resp.IsSuccessStatusCode)
                {
                    string err = $"PeeringDB returned HTTP {(int)resp.StatusCode} for info_type={infoType}";
                    return (all, pageCount == 1 ? err : null);
                }

                var json = await resp.Content.ReadAsStringAsync(ct);
                using var doc = JsonDocument.Parse(json);
                var page = doc.RootElement.GetProperty("data").EnumerateArray()
                    .Select(n => ParseNetwork(n))
                    .Where(c => c != null)
                    .Select(c => c!)
                    .ToList();
                all.AddRange(page);
                if (page.Count < pageSize) break;
                await Task.Delay(400, ct);
                skip += pageSize;
            }
        }
        await SavePeeringDbCacheAsync(infoType, all, ct);
        return (all, null);
    }

    // Rate limiter shared across all RIPE Stat calls in this instance — avoids HTTP 429.
    // Each candidate in Phase A acquires it twice (prefix + neighbour) concurrently,
    // so the count must be >= 2 × MaxDegreeOfParallelism to avoid potential deadlock.
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

        // Phase A: RIPE prefixes + neighbours run simultaneously per candidate.
        // ASN type check is a local map lookup (as.json + bgp.tools) — no network call.
        await Parallel.ForEachAsync(candidates,
            new ParallelOptions { MaxDegreeOfParallelism = 10, CancellationToken = ct },
            async (candidate, innerCt) =>
            {
                IReadOnlyList<string>? localPrefixes = null;
                localPrefixFallback?.TryGetValue(candidate.Asn, out localPrefixes);
                var prefixTask    = FetchPrefixDataAsync(candidate.Asn, localPrefixes, innerCt);
                var neighbourTask = FetchNeighboursAsync(candidate.Asn, innerCt);

                await Task.WhenAll(prefixTask, neighbourTask);

                // Get prefix data first — needed for the IP pool threshold in the filter below.
                var (ipv4, ipv6)  = prefixTask.Result;
                var (upstream, _) = neighbourTask.Result;
                if (ipv4.Count == 0) return;
                long totalIps = Ipv4RangeMath.CountUniqueAddresses(ipv4);

                // Principled hosting filter (applied when --type server/vps/cloud is used):
                //
                //  Whitelist (ipcat + cloud-providers + server-ips) → always passes.
                //
                //  NSP (transit/ISP networks): strict — require ipapi.is "hosting"/"cloud".
                //    Rationale: ISPs vastly outnumber hosting NSPs; false positives are common.
                //
                //  Content: lenient with targeted exclusions.
                //    Pass:   ipapi.is "hosting"/"cloud", or null with ≥1024 IPs (benefit of doubt).
                //    Reject: ipapi.is explicitly non-hosting (isp/cable/cdn/government/education),
                //            or null with <1024 IPs (micro-networks unlikely to be real VPS providers).
                //
                // This avoids maintaining hand-curated name/ASN exclusion lists while still
                // filtering TELE2 (isp), Disney (cdn), tiny junk networks, etc.
                // Hard block: non-hosting companies (Apple, Netflix, Meta) never appear in results.
                if (IsNonHostingProvider(candidate)) return;

                // Hard block: AI/GPU-only cloud providers (CoreWeave, Lambda, Crusoe, etc.) are
                // never included when --type excludes AI (server/vps/dedicated/cloud) — this must
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

                    // Explicit non-hosting verdicts reject BEFORE the whitelist check:
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
        IReadOnlyList<string> ipv4 = [];
        IReadOnlyList<string> ipv6 = [];
        bool ripeOk   = false;
        bool acquired = false;
        try
        {
            await _ripeSemaphore.WaitAsync(ct);
            acquired = true;
            (ripeOk, ipv4, ipv6) = await ripeClient.GetAllPrefixesAsync(asn, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }
        finally { if (acquired) _ripeSemaphore.Release(); }

        if (ipv4.Count == 0 && localPrefixes is { Count: > 0 })
            ipv4 = localPrefixes;

        // BGPView fallback: RIPE Stat and local data returned no IPv4 prefixes for this ASN.
        // Throttled to ~42 req/min — only triggered for genuinely missing ASNs.
        // Preserves any IPv6 data already returned by RIPE Stat.
        // Known-empty ASNs (pfx0 marker) skip the throttled call within the cache TTL —
        // otherwise ~100 serialized fallback requests add minutes to every run.
        if (ipv4.Count == 0 && _bgpView != null && !ripeClient.IsKnownEmpty(asn))
        {
            var (bgpOk, bgpIpv4, bgpIpv6) = await _bgpView.GetPrefixesAsync(asn, ct);
            ipv4 = bgpIpv4;
            if (ipv6.Count == 0) ipv6 = bgpIpv6;

            if (ipv4.Count > 0) ripeClient.CachePrefixes(asn, ipv4, ipv6); // fallback hit → same pfx_ key
            // WR-01: полный 24ч-маркер только при ПОДТВЕРЖДЁННОЙ пустоте — оба источника
            // успешно ответили «префиксов нет». Двойной транзиентный сбой (общая сетевая
            // деградация, двойной rate-limit) больше не помечает здоровый ASN как пустой на 24ч.
            // Неподтверждённая пустота получает КОРОТКИЙ маркер (1ч): без него каждый
            // прогон заново шёл в сериализованный BGPView (1.4с/ASN) — при системном
            // отказе BGPView это минуты на КАЖДЫЙ прогон вместо одного часового окна.
            else if (ripeOk && bgpOk) ripeClient.MarkEmpty(asn);
            else                      ripeClient.MarkEmpty(asn, TimeSpan.FromHours(1));
        }

        return (ipv4, ipv6);
    }

    private async Task<(int Upstream, int Downstream)> FetchNeighboursAsync(
        uint asn, CancellationToken ct)
    {
        bool acquired = false;
        try
        {
            await _ripeSemaphore.WaitAsync(ct);
            acquired = true;
            return await ripeClient.GetNeighbourCountsAsync(asn, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return (0, 0); }
        finally { if (acquired) _ripeSemaphore.Release(); }
    }

    public static long CountIpsInCidr(string cidr)
        => Ipv4RangeMath.CountAddresses(cidr);

    // Стабы для ASN из asnList, не давших кандидата в цикле обогащения: только те, что
    // есть в nameFallback (имена ядра) — не-core сюда попасть не может. Префиксы добьёт
    // localPrefixFallback в EnrichWithPrefixesAsync. Гарантирует, что core-член не теряется
    // из-за 429/ошибки PeeringDB. Чистая функция — тестируется изолированно.
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
    // Unlike FindGlobalAsync, this goes from IPs → ASNs → PeeringDB, not the other way round.
    // When infoTypes is non-null (e.g. --type vps), only matching PeeringDB entries pass.
    // ASNs not in PeeringDB are included as fallback only when no type filter is active.
    public async Task<IReadOnlyList<ProviderCandidate>> FindByAsnListAsync(
        IReadOnlyList<(uint Asn, int Coverage)> asnList,
        string[]? infoTypes = null,
        bool excludeCdn = false,
        bool excludeAi = false,
        HashSet<uint>? localHostingWhitelist = null,
        Action<string>? onError = null,
        Action<int, int, int>? onDiagnostic = null, // (inputCount, afterIpapiFilter, sentToPeeringDb)
        IReadOnlyDictionary<uint, IReadOnlyList<string>>? localPrefixFallback = null,
        IReadOnlyDictionary<uint, string>? nameFallback = null,
        CancellationToken ct = default)
    {
        // CDN exclusion is absolute — remove known CDN ASNs regardless of local whitelist.
        if (excludeCdn && asnList.Any(a => _excl.KnownCdnAsns.Contains(a.Asn)))
            asnList = asnList.Where(a => !_excl.KnownCdnAsns.Contains(a.Asn)).ToList();

        bool hasTypeFilter = infoTypes is { Length: > 0 };

        // When a type filter is active, pre-filter by local ASN type BEFORE touching PeeringDB.
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

        var candidates = new System.Collections.Concurrent.ConcurrentBag<ProviderCandidate>();
        int rateLimitReported = 0;

        // Cap PeeringDB requests to avoid rate limiting.
        // Trusted ASNs (from local hosting files, whitelist provided) → no cap needed.
        // If ipapi.is filtered >30% of inputs → no cap (it did its job).
        // Otherwise (random user IPs, no filter) → cap at 50 as safety net.
        bool ipapiFiltered = enrichList.Count < asnList.Count * 0.7;
        bool trustedAsns   = localHostingWhitelist != null;
        int peeringDbCap   = (ipapiFiltered || trustedAsns) ? enrichList.Count : 50;
        var peeringDbList  = enrichList.Take(peeringDbCap).ToList();

        // Lower parallelism to stay within PeeringDB anonymous rate limits.
        await Parallel.ForEachAsync(peeringDbList,
            new ParallelOptions { MaxDegreeOfParallelism = 3, CancellationToken = ct },
            async (entry, innerCt) =>
            {
                ProviderCandidate? candidate = null;
                bool foundInPeeringDb = false;
                bool haveRecord = false;

                // Cache-aside: the supplement ASN sets are stable across runs, so without a
                // cache the same per-ASN /net?asn= lookups repeat every run (DoP=3 ≈ 5s for 40).
                // The RAW record is cached pre-filter so per-call type/CDN filters below apply.
                if (_ripeCache != null && _ripeCache.TryGet($"pdb_{entry.Asn}", out var cachedNet))
                {
                    var rec = DeserializePdbNetOrNull(cachedNet!);
                    if (rec != null)
                    {
                        haveRecord       = true;
                        foundInPeeringDb = rec.Found;
                        if (rec.Found && rec.Name != null)
                            candidate = new ProviderCandidate(
                                entry.Asn, rec.Name, rec.Country, rec.Website,
                                rec.InfoType, rec.PeeringCount, null, []);
                    }
                }

                if (!haveRecord)
                {
                    try
                    {
                        using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(innerCt);
                        reqCts.CancelAfter(TimeSpan.FromSeconds(5));
                        using var req = PdbRequest($"{PeeringDbBase}/net?asn={entry.Asn}&status=ok");
                        using var resp = await peeringDbHttp.SendAsync(req, reqCts.Token);

                        if (resp.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                        {
                            // Report only once — every parallel slot would hit 429 simultaneously.
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
                        // Cache successful lookups only (found or genuinely absent) —
                        // errors/timeouts above returned early or fall to catch.
                        _ripeCache?.Set($"pdb_{entry.Asn}",
                            SerializePdbNet(candidate, foundInPeeringDb), PeeringDbCacheTtl);
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch { }
                }

                // Per-call filters — applied to both fresh and cached records.
                if (candidate != null && hasTypeFilter &&
                    !infoTypes!.Contains(candidate.InfoType ?? "", StringComparer.OrdinalIgnoreCase))
                    candidate = null;
                if (candidate != null && excludeCdn && IsCdnProvider(candidate))
                    candidate = null;

                // Fallback: only when PeeringDB genuinely has NO record for this ASN.
                // Do NOT fall back when we explicitly excluded the ASN (CDN/type filter) —
                // that would bypass the exclusion via the RIPE Stat path (Cloudflare bug).
                if (candidate == null && !foundInPeeringDb && !hasTypeFilter)
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

                if (candidate != null)
                    candidates.Add(candidate with { CoverageCount = entry.Coverage });
            });

        // Backfill именами из ядра: любой ASN, не давший кандидата в цикле (PeeringDB 429/ошибка/
        // ранний return/нет записи и RIPE overview молчит), добавляем стабом с именем из ядра —
        // префиксы добьёт localPrefixFallback в EnrichWithPrefixesAsync. Так core-член не теряется.
        foreach (var stub in BackfillNameStubs(
                     asnList, new HashSet<uint>(candidates.Select(c => c.Asn)), nameFallback))
            candidates.Add(stub);

        onDiagnostic?.Invoke(asnList.Count, enrichList.Count, peeringDbList.Count);

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
