using System.Text.Json;
using SubnetSearch.Core.Models.Network;
using SubnetSearch.Network.Http;
using SubnetSearch.Network.Reputation;

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
    IpapiIsClient?  asnTypeClient = null,
    AsnExclusions?  exclusions    = null,
    BgpViewClient?  bgpView       = null)
{
    private readonly AsnExclusions  _excl    = exclusions ?? AsnExclusions.Default;
    private readonly BgpViewClient? _bgpView = bgpView;

    private const string PeeringDbBase = "https://www.peeringdb.com/api";

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
        _                                                                       => null,
    };

    // When --type server (and its aliases) is used, exclude pure CDN providers from results.
    public static bool ShouldExcludeCdn(string? typeFilter) =>
        typeFilter?.ToLowerInvariant() is "server" or "hosting" or "vps" or "dedicated" or "cloud";

    public const string ValidTypeValues =
        "server                        — all server rental (VPS, dedicated, cloud) [aliases: hosting, vps, dedicated, cloud]\n" +
        "                         cdn / content    — CDN and content networks\n" +
        "                         nsp / isp / transit  — Network service providers";

    private bool IsNonHostingProvider(ProviderCandidate c) => _excl.NonHostingAsns.Contains(c.Asn);
    private bool IsCdnProvider(ProviderCandidate c)        => _excl.KnownCdnAsns.Contains(c.Asn);

    // Global search: fetches all hosting/content networks from PeeringDB directly.
    // Returns top candidates sorted by peering count, enriched with prefixes.
    // onPreEnrichment: called with (perTypeCounts, errors, totalBeforeEnrich) for diagnostics.
    // countryCodes: optional list of ISO country codes to filter by (e.g. ["DE","NL","FI"]).
    public async Task<IReadOnlyList<ProviderCandidate>> FindGlobalAsync(
        string[]? countryCodes = null,
        int topN = 300,
        string[]? infoTypes = null,
        bool excludeCdn = false,
        HashSet<uint>? localHostingWhitelist = null,
        Action<Dictionary<string, int>, IReadOnlyList<string>, int>? onPreEnrichment = null,
        CancellationToken ct = default)
    {
        // PeeringDB info_type values are case-sensitive: "Content", "NSP".
        // NOTE: "Hosting" is intentionally omitted — PeeringDB has no networks with that type.
        // Requests are sequential to avoid triggering PeeringDB rate limits from parallel bursts.
        var types   = infoTypes ?? ["Content", "NSP"];
        var fetches = new List<(IReadOnlyList<ProviderCandidate> Candidates, string? Error)>();
        foreach (var t in types)
            fetches.Add(await FetchNetsByTypeAsync(t, ct));

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

        var top = all.ToList();

        onPreEnrichment?.Invoke(perType, errors, top.Count);

        // When hosting filter is active, pre-filter by ipapi.is type BEFORE RIPE Stat calls.
        // Whitelist ASNs (confirmed local hosting files) → pass without ipapi.is call (saves quota).
        // Non-whitelist ASNs → must have explicit "hosting"/"cloud" type; null → rejected.
        // Fallback: if ipapi.is is down (all results null), skip the pre-filter entirely and
        // fall back to balanced filtering in EnrichWithPrefixesAsync.
        bool ipapiPreFilterActive = false;
        if (excludeCdn && asnTypeClient != null)
        {
            var preFiltered = new System.Collections.Concurrent.ConcurrentBag<ProviderCandidate>();
            int nullCount = 0, passCount = 0;
            await Parallel.ForEachAsync(top,
                new ParallelOptions { MaxDegreeOfParallelism = 15, CancellationToken = ct },
                async (candidate, innerCt) =>
                {
                    if (localHostingWhitelist?.Contains(candidate.Asn) ?? false)
                    {
                        preFiltered.Add(candidate); // confirmed hosting — skip ipapi.is
                        Interlocked.Increment(ref passCount);
                        return;
                    }
                    var info = await asnTypeClient.GetAsnInfoAsync(candidate.Asn, innerCt);
                    if (info.Type is "hosting" or "cloud")
                    {
                        preFiltered.Add(candidate);
                        Interlocked.Increment(ref passCount);
                    }
                    else if (info.Type == null)
                        Interlocked.Increment(ref nullCount);
                });

            // If ipapi.is appears to be down (>80% of non-whitelisted calls returned null),
            // skip the pre-filter. passCount includes whitelisted ASNs (always pass), so
            // use nullCount vs non-whitelisted total to detect service outage.
            int nonWhitelisted = top.Count(c => !(localHostingWhitelist?.Contains(c.Asn) ?? false));
            bool ipapiDown = nonWhitelisted > 5 && nullCount > nonWhitelisted * 0.8;
            if (!ipapiDown)
            {
                top = [.. preFiltered.OrderByDescending(c => c.PeeringCount ?? 0)];
                ipapiPreFilterActive = true;
            }
        }

        // Pre-filter already handled type checking — skip redundant check in EnrichWithPrefixesAsync.
        // If pre-filter was skipped (ipapi.is down), use balanced filter as fallback.
        return await EnrichWithPrefixesAsync(top, ct,
            filterHostingOnly: !ipapiPreFilterActive && excludeCdn,
            localHostingWhitelist: localHostingWhitelist,
            strictContentFilter: false);
    }

    // Regional search: finds networks present at IXPs matching the region name.
    public async Task<IReadOnlyList<ProviderCandidate>> FindByRegionAsync(
        string region, string[]? infoTypes = null, bool excludeCdn = false,
        HashSet<uint>? localHostingWhitelist = null, CancellationToken ct = default)
    {
        List<int> ixIds;
        try
        {
            using var ixResp = await peeringDbHttp.GetAsync(
                $"{PeeringDbBase}/ix?name_search={Uri.EscapeDataString(region)}&status=ok", ct);
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
                using var lanResp = await peeringDbHttp.GetAsync(
                    $"{PeeringDbBase}/netixlan?ix_id={ixId}&status=ok", ct);
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
                    using var netResp = await peeringDbHttp.GetAsync(
                        $"{PeeringDbBase}/net/{netId}", innerCt);
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
        if (excludeCdn)
            candidates = candidates.Where(c => !IsCdnProvider(c));

        return await EnrichWithPrefixesAsync([.. candidates], ct,
            filterHostingOnly: excludeCdn, localHostingWhitelist: localHostingWhitelist);
    }

    // PeeringDB defaults to 250 records per page. Paginate with skip until all records are fetched.
    // Returns (candidates, errorMessage) — error is non-null when the first page fails.
    private async Task<(IReadOnlyList<ProviderCandidate> Candidates, string? Error)> FetchNetsByTypeAsync(
        string infoType, CancellationToken ct)
    {
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

                    resp = await peeringDbHttp.GetAsync(url, reqCts.Token);

                    if (resp.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                    {
                        var retryAfter = resp.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(15);
                        resp.Dispose(); resp = null;
                        await Task.Delay((int)Math.Min(retryAfter.TotalMilliseconds, 30_000), ct);
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
                skip += pageSize;
            }
        }
        return (all, null);
    }

    // Rate limiter shared across all RIPE Stat calls in this instance — avoids HTTP 429.
    private readonly SemaphoreSlim _ripeSemaphore = new(10, 10);

    private async Task<IReadOnlyList<ProviderCandidate>> EnrichWithPrefixesAsync(
        IReadOnlyList<ProviderCandidate> candidates, CancellationToken ct,
        bool filterHostingOnly = false,
        HashSet<uint>? localHostingWhitelist = null,
        bool strictContentFilter = false)
    {
        var withPrefixes = new System.Collections.Concurrent.ConcurrentBag<ProviderCandidate>();

        // Phase A: RIPE prefixes + neighbours + ipapi.is type run simultaneously per candidate.
        // ipapi.is type check is only performed when filterHostingOnly=true (--type vps/hosting).
        await Parallel.ForEachAsync(candidates,
            new ParallelOptions { MaxDegreeOfParallelism = 10, CancellationToken = ct },
            async (candidate, innerCt) =>
            {
                // All three tasks start immediately — each rate-limited by its own throttle.
                var prefixTask    = FetchPrefixDataAsync(candidate.Asn, innerCt);
                var neighbourTask = FetchNeighboursAsync(candidate.Asn, innerCt);
                var typeTask      = filterHostingOnly && asnTypeClient != null
                    ? asnTypeClient.GetAsnInfoAsync(candidate.Asn, innerCt)
                    : Task.FromResult(new AsnInfo(null, null));

                await Task.WhenAll(prefixTask, neighbourTask, typeTask);

                // Get prefix data first — needed for the IP pool threshold in the filter below.
                var (ipv4, ipv6)  = prefixTask.Result;
                var (upstream, _) = neighbourTask.Result;
                if (ipv4.Count == 0) return;
                long totalIps = ipv4.Sum(CountIpsInCidr);

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

                if (filterHostingOnly)
                {
                    // Hard block: CDN ASNs are never included regardless of whitelist.
                    if (IsCdnProvider(candidate)) return;

                    var asnType      = typeTask.Result.Type;
                    bool inWhitelist = localHostingWhitelist?.Contains(candidate.Asn) ?? false;

                    if (!inWhitelist)
                    {
                        bool isNsp = string.Equals(candidate.InfoType, "NSP",
                            StringComparison.OrdinalIgnoreCase);

                        if (isNsp)
                        {
                            if (asnType is not ("hosting" or "cloud"))
                                return;
                        }
                        else // Content
                        {
                            // Reject confirmed non-hosting types
                            if (asnType is ("isp" or "cable" or "cdn" or
                                            "government" or "education" or "inactive"))
                                return;
                            // Strict mode (PeeringDB global, no local whitelist):
                            //   reject Content with unknown ipapi.is type — no benefit of doubt.
                            //   This blocks Sony, Meta, Google subsidiaries, registries, etc.
                            // Lenient mode (local-whitelist path):
                            //   allow null type with ≥1024 IPs (benefit of doubt for real providers).
                            if (asnType == null)
                            {
                                if (strictContentFilter || totalIps < 1024) return;
                            }
                        }
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

        // Phase B: RPKI — sample first prefix only to limit RIPE Stat load.
        var results = new System.Collections.Concurrent.ConcurrentBag<ProviderCandidate>();
        await Parallel.ForEachAsync(withPrefixes,
            new ParallelOptions { MaxDegreeOfParallelism = 10, CancellationToken = ct },
            async (candidate, innerCt) =>
            {
                bool acquired = false;
                try
                {
                    await _ripeSemaphore.WaitAsync(innerCt);
                    acquired = true;
                    var rpki = await ripeClient.GetRpkiValidityRatioAsync(
                        candidate.Prefixes, maxSample: 2, ct: innerCt);
                    results.Add(candidate with { RpkiScore = rpki });
                }
                catch (OperationCanceledException) when (innerCt.IsCancellationRequested) { throw; }
                catch
                {
                    results.Add(candidate);
                }
                finally { if (acquired) _ripeSemaphore.Release(); }
            });

        return [.. results];
    }

    private async Task<(IReadOnlyList<string> IPv4, IReadOnlyList<string> IPv6)> FetchPrefixDataAsync(
        uint asn, CancellationToken ct)
    {
        IReadOnlyList<string> ipv4 = [];
        IReadOnlyList<string> ipv6 = [];
        bool acquired = false;
        try
        {
            await _ripeSemaphore.WaitAsync(ct);
            acquired = true;
            (ipv4, ipv6) = await ripeClient.GetAllPrefixesAsync(asn, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }
        finally { if (acquired) _ripeSemaphore.Release(); }

        // BGPView fallback: RIPE Stat returned no IPv4 prefixes for this ASN.
        // Throttled to ~42 req/min — only triggered for genuinely missing ASNs.
        if (ipv4.Count == 0 && _bgpView != null)
            (ipv4, ipv6) = await _bgpView.GetPrefixesAsync(asn, ct);

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

    private static long CountIpsInCidr(string cidr)
    {
        var slash = cidr.IndexOf('/');
        if (slash < 0) return 1;
        if (!int.TryParse(cidr[(slash + 1)..], out int prefix) || prefix < 0 || prefix > 32) return 1;
        return 1L << (32 - prefix);
    }

    // IP-list mode: find providers for a pre-computed list of (ASN, coverageCount) pairs.
    // Unlike FindGlobalAsync, this goes from IPs → ASNs → PeeringDB, not the other way round.
    // When infoTypes is non-null (e.g. --type vps), only matching PeeringDB entries pass.
    // ASNs not in PeeringDB are included as fallback only when no type filter is active.
    public async Task<IReadOnlyList<ProviderCandidate>> FindByAsnListAsync(
        IReadOnlyList<(uint Asn, int Coverage)> asnList,
        string[]? infoTypes = null,
        bool excludeCdn = false,
        HashSet<uint>? localHostingWhitelist = null,
        Action<string>? onError = null,
        Action<int, int, int>? onDiagnostic = null, // (inputCount, afterIpapiFilter, sentToPeeringDb)
        CancellationToken ct = default)
    {
        // CDN exclusion is absolute — remove known CDN ASNs regardless of local whitelist.
        if (excludeCdn && asnList.Any(a => _excl.KnownCdnAsns.Contains(a.Asn)))
            asnList = asnList.Where(a => !_excl.KnownCdnAsns.Contains(a.Asn)).ToList();

        bool hasTypeFilter = infoTypes is { Length: > 0 };

        // When a type filter is active, pre-filter by ipapi.is BEFORE touching PeeringDB.
        // This prevents burning the PeeringDB rate limit on ISPs that EnrichWithPrefixesAsync
        // would eliminate anyway. ISPs return type="isp"/"cable" and are dropped here cheaply.
        // Unknown types (null) get benefit of the doubt and proceed to PeeringDB.
        var enrichList = asnList;
        if (hasTypeFilter && asnTypeClient != null)
        {
            var passing = new System.Collections.Concurrent.ConcurrentBag<(uint Asn, int Coverage)>();
            await Parallel.ForEachAsync(asnList,
                new ParallelOptions { MaxDegreeOfParallelism = 3, CancellationToken = ct },
                async (entry, innerCt) =>
                {
                    var info = await asnTypeClient.GetAsnInfoAsync(entry.Asn, innerCt);
                    if (info.Type != null && info.Type is not ("hosting" or "cloud"))
                        return;
                    passing.Add(entry);
                });
            enrichList = [.. passing.OrderByDescending(a => a.Coverage)];
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
                try
                {
                    using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(innerCt);
                    reqCts.CancelAfter(TimeSpan.FromSeconds(5));
                    using var resp = await peeringDbHttp.GetAsync(
                        $"{PeeringDbBase}/net?asn={entry.Asn}&status=ok", reqCts.Token);

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
                        if (hasTypeFilter && candidate != null &&
                            !infoTypes!.Contains(candidate.InfoType ?? "",
                                StringComparer.OrdinalIgnoreCase))
                            candidate = null;

                        if (excludeCdn && candidate != null && IsCdnProvider(candidate))
                            candidate = null;
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch { }

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

        onDiagnostic?.Invoke(asnList.Count, enrichList.Count, peeringDbList.Count);

        return await EnrichWithPrefixesAsync([.. candidates], ct,
            filterHostingOnly: excludeCdn, localHostingWhitelist: localHostingWhitelist);
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
