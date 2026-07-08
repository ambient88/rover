using SubnetSearch.Classification;
using SubnetSearch.Network;
using SubnetSearch.Network.Http;
using SubnetSearch.Network.Recommend;
using SubnetSearch.Network.Reputation;
using SubnetSearch.Cli.Rendering;

namespace SubnetSearch.Cli.Commands;

public sealed class RecommendCommand(
    CliContext ctx, string? region, int? maxPing,
    string? countryFilter, int returnTop, string? typeFilter,
    string? sortBy, string? traceTo, string? fromSource, string? preset) : ICommand
{
    public async Task<int> ExecuteAsync(CancellationToken ct)
    {
        // WR-04: flush кэша в finally — любое исключение внутри поиска (сбой запуска
        // ping, необработанная сетевая ошибка, Ctrl+C) не должно терять сотни
        // накопленных за прогон RIPE/PeeringDB/ping-ответов: смысл кэша — переживать
        // неудачные прогоны. Отравленные негативные записи при сбоях больше не пишутся
        // (CR-01/WR-01/WR-03), поэтому flush безопасен и на пути ошибки.
        var ripeCache = await RipeStatCache.LoadAsync(ctx.DataDir);
        try
        {
            return await ExecuteWithCacheAsync(ripeCache, ct);
        }
        finally
        {
            await ripeCache.FlushIfDirtyAsync();
        }
    }

    private async Task<int> ExecuteWithCacheAsync(RipeStatCache ripeCache, CancellationToken ct)
    {
        // Original HandleRecommend parameters map to CliContext + parsed args.
        // Aliased to locals so the transferred body stays verbatim and the Spectre
        // Status lambda parameter `ctx` (which shadows the primary-ctor CliContext)
        // never collides with the CliContext accessors.
        var dataDir       = ctx.DataDir;
        var peeringDbHttp = ctx.PeeringDbHttp;
        var config        = ctx.Config;
        var maxPingMs     = maxPing;

        bool isGlobal  = string.IsNullOrWhiteSpace(region);
        var infoTypes  = ProviderFinder.ResolveInfoTypes(typeFilter); // null = no filter (all types)

        // Parse comma-separated country codes: "DE,NL,FI" → ["DE","NL","FI"]
        string[]? countryCodes = countryFilter?
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(c => c.ToUpperInvariant())
            .ToArray();
        string? countryDisplay = countryCodes?.Length > 0 ? string.Join(",", countryCodes) : null;

        string title   = isGlobal
            ? (countryDisplay != null ? countryDisplay : "Worldwide")
            : region!;

        AnsiConsole.MarkupLine($"[cyan]Finding providers: {Markup.Escape(title)}[/]");
        if (typeFilter != null)
            AnsiConsole.MarkupLine($"[dim]Type: {Markup.Escape(typeFilter)} → {Markup.Escape(string.Join(", ", infoTypes ?? []))}[/]");
        if (maxPingMs.HasValue)
            AnsiConsole.MarkupLine($"[dim]Max ping: {maxPingMs.Value} ms[/]");
        AnsiConsole.MarkupLine($"[dim]Top: {returnTop}[/]");
        if (preset != null)
            AnsiConsole.MarkupLine($"[dim]Preset: {Markup.Escape(preset)}[/]");
        if (sortBy?.ToLowerInvariant() == "coverage" && string.IsNullOrWhiteSpace(fromSource))
            AnsiConsole.MarkupLine("[yellow]Note: --sort coverage requires --from; falling back to score.[/]");
        Console.WriteLine();


        var ripeClient = new RipeStatClient(peeringDbHttp, ripeCache);
        var spamhaus   = new SpamhausDropClient(peeringDbHttp);
        var ipapiIs    = new IpapiIsClient(peeringDbHttp);
        var abuseIpDb  = config.AbuseIpDbKey != null ? new AbuseIpDbClient(peeringDbHttp, config.AbuseIpDbKey) : null;
        var greyNoise  = config.GreyNoiseKey  != null ? new GreyNoiseClient(peeringDbHttp, config.GreyNoiseKey)  : null;

        var ipsumData  = await new IpsumLoader().LoadAsync(Path.Combine(dataDir, "ipsum.txt"));
        var ipsum      = new IpsumReputationChecker(ipsumData);
        var exclusions = await AsnExclusions.LoadAsync(Path.Combine(dataDir, "asn-exclusions.json"));

        var ip2asnRecords = await new Ip2AsnLoader().LoadAsync(Path.Combine(dataDir, "ip2asn-v4.tsv.gz"));
        var recoIpIndex   = new IpRangeIndex(ip2asnRecords);

        var caidaData  = await CaidaClassificationLoader.LoadAsync(
                             Path.Combine(dataDir, "as-classification.txt.gz"));

        // Локальная карта asn → тип: as.json (ipverse) + bgp.tools tags вместо сетевых
        // запросов к ipapi.is (эндпоинт умирал молча, а квота 1000/день сгорала за один прогон).
        var asJsonCategories = await new AsnMetadataParser().LoadCategoriesAsync(Path.Combine(dataDir, "as.json"));
        var bgpToolsTags     = await BgpToolsTagLoader.LoadAllAsync(dataDir);
        var asnTypes         = AsnTypeResolver.Build(bgpToolsTags, asJsonCategories);

        // Allowlist-модель server-фильтров (спека 2026-07-08, pure-allowlist ревизия):
        // членство в --type vps/dedicated/cloud/server даёт ТОЛЬКО курируемое ядро
        // server-providers.json (+ .local.json override). Авто-гейт по vpsh-тегу убран —
        // ничего не проходит автоматически, только проверенные арендуемые провайдеры.
        var serverProviders = await ServerProviders.LoadAsync(
                                  Path.Combine(dataDir, "server-providers.json"),
                                  Path.Combine(dataDir, "server-providers.local.json"));

        var bgpView    = new BgpViewClient(peeringDbHttp);
        var finder     = new ProviderFinder(peeringDbHttp, ripeClient, asnTypes, exclusions, bgpView, dataDir, caidaData, ripeCache);
        var pingSvc    = new PingService();
        var scorer     = new ProviderScorer(spamhaus, ipapiIs, ipsum, pingSvc, abuseIpDb, greyNoise, ripeCache);
        var indexCache = new ProviderIndexCache(dataDir);

        IReadOnlyList<ProviderRecommendation> results = [];

        int diagnosticCandidates = 0;
        int diagnosticAfterRipe  = 0;
        Dictionary<string, int>? diagnosticPerType = null;
        IReadOnlyList<string> diagnosticErrors = [];
        int diagnosticPreEnrich = 0;

        int totalListIps = 0;
        Dictionary<uint, int>? coverageMap = null;

        // --from: build coverage map independently, then run the same global search as always.
        // Coverage is applied as an annotation after scoring — not a separate search pipeline.
        IReadOnlyList<(uint Asn, int Count)> fromAsnList = [];
        if (!string.IsNullOrWhiteSpace(fromSource))
        {
            // Фолбэк-маршрут для URL-источников: peeringDbHttp привязан к физическому
            // интерфейсу (мимо VPN), и заблокированные провайдером хосты
            // (raw.githubusercontent.com) на нём падают с «SSL connection could not be
            // established». Обычный HttpClient идёт системным маршрутом — через VPN.
            using var systemRouteHttp = new HttpClient();
            systemRouteHttp.DefaultRequestHeaders.UserAgent.ParseAdd("rover/1.0");
            try
            {
                var text = await IpListAnalyzer.ReadSourceAsync(
                    fromSource, peeringDbHttp, ct, fallbackHttp: systemRouteHttp);
                var ips  = IpListAnalyzer.ExtractIps(text);
                if (ips.Count == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]--from: no IPv4 addresses found in the source.[/]");
                }
                else
                {
                    fromAsnList  = IpListAnalyzer.AggregateByAsn(ips, recoIpIndex);
                    totalListIps = ips.Count;
                    coverageMap  = fromAsnList.ToDictionary(a => a.Asn, a => a.Count);
                    AnsiConsole.MarkupLine(
                        $"[dim]--from: {ips.Count} IPs → {fromAsnList.Count} ASNs (coverage map ready)[/]");
                }
            }
            catch (Exception ex)
            {
                // Внешнее сообщение вида «The SSL connection could not be established,
                // see inner exception» без inner бесполезно — разворачиваем до корня.
                var msg = ex.Message;
                if (ex.InnerException != null)
                    msg += $" ← {ex.GetBaseException().Message}";
                AnsiConsole.MarkupLine($"[yellow]--from: could not load source — {Markup.Escape(msg)}[/]");
            }
        }

        bool needsHostingFilter = ProviderFinder.ShouldExcludeCdn(typeFilter);
        bool needsAiExclusion   = ProviderFinder.ShouldExcludeAi(typeFilter);
        bool aiOnly             = ProviderFinder.ShouldFilterAiOnly(typeFilter);
        IReadOnlyList<(uint Asn, int Count)>? localHostingAsns = null;

        await AnsiConsole.Status()
            .StartAsync("Searching...", async ctx =>
            {
                IReadOnlyList<ProviderCandidate> candidates;

                if (isGlobal && needsHostingFilter)
                {
                    // --type server: single bulk PeeringDB request + local whitelist.
                    //
                    // BULK PeeringDB fetch (3 requests: Content/NSP/Hosting) with pre-filter:
                    //   - Local whitelist ASNs → pass without ipapi.is call (confirmed hosting files).
                    //   - All others → must have ipapi.is type "hosting" or "cloud".
                    //   Rejects: Disney, TELE2, Sony, Meta, Cisco (isp/cdn/null → rejected).
                    //
                    // SUPPLEMENT: local ASNs not in PeeringDB's top-N → RIPE Stat fallback (up to 40).
                    ctx.Status("Loading confirmed hosting providers from local databases...");
                    localHostingAsns = await GetLocalHostingAsnsAsync(dataDir);
                    var localWhitelist = new HashSet<uint>(localHostingAsns.Select(a => a.Asn));

                    ctx.Status("Fetching providers from PeeringDB (3 bulk requests)...");
                    candidates = [.. await finder.FindGlobalAsync(
                        countryCodes, topN: Math.Max(returnTop * 15, 1000), infoTypes: infoTypes,
                        excludeCdn: true, excludeAi: needsAiExclusion, aiOnly: aiOnly,
                        localHostingWhitelist: localWhitelist,
                        onPreEnrichment: (perType, errors, total) =>
                        {
                            diagnosticPerType   = perType;
                            diagnosticErrors    = errors;
                            diagnosticPreEnrich = total;
                        },
                        onStatus: msg => ctx.Status(msg),
                        ct: ct)];

                    // Supplement: local ASNs missed by the top-N bulk result.
                    var foundAsns = new HashSet<uint>(candidates.Select(c => c.Asn));
                    var missing   = localHostingAsns
                        .Where(a => !foundAsns.Contains(a.Asn))
                        .Take(Math.Max(returnTop, 40))
                        .ToList();
                    if (missing.Count > 0)
                    {
                        ctx.Status($"Supplementing {missing.Count} local providers via RIPE Stat...");
                        var extra = await finder.FindByAsnListAsync(
                            missing, infoTypes: null, excludeCdn: needsHostingFilter,
                            excludeAi: needsAiExclusion,
                            localHostingWhitelist: localWhitelist, ct: ct);
                        candidates = [.. candidates.Concat(extra).DistinctBy(c => c.Asn)];
                    }
                }
                else if (isGlobal)
                {
                    // No hosting filter: PeeringDB global discovery + local file supplement.
                    ctx.Status("Fetching all hosting networks from PeeringDB...");
                    candidates = await finder.FindGlobalAsync(
                        countryCodes, topN: Math.Max(returnTop * 5, 300), infoTypes: infoTypes,
                        excludeCdn: false, excludeAi: needsAiExclusion, aiOnly: aiOnly,
                        onPreEnrichment: (perType, errors, total) =>
                        {
                            diagnosticPerType   = perType;
                            diagnosticErrors    = errors;
                            diagnosticPreEnrich = total;
                        },
                        onStatus: msg => ctx.Status(msg),
                        ct: ct);

                    // Supplement with local hosting DB only for unfiltered search (no --type).
                    // For --type cdn or --type transit, hosting supplements add wrong provider types:
                    // IaaS/datacenter ASNs would appear in CDN results, hosting in transit results.
                    if (typeFilter == null)
                    {
                        var globalAsns = new HashSet<uint>(candidates.Select(c => c.Asn));
                        ctx.Status("Supplementing from local datacenter databases...");
                        localHostingAsns = await GetLocalHostingAsnsAsync(dataDir);
                        var supplement = localHostingAsns.Where(a => !globalAsns.Contains(a.Asn)).Take(60).ToList();
                        if (supplement.Count > 0)
                        {
                            var extra = await finder.FindByAsnListAsync(supplement,
                                infoTypes: null, excludeCdn: false, excludeAi: needsAiExclusion,
                                localHostingWhitelist: new HashSet<uint>(supplement.Select(a => a.Asn)), ct: ct);
                            candidates = [.. candidates.Concat(extra).DistinctBy(c => c.Asn)];
                        }
                    }
                }
                else
                {
                    ctx.Status($"Looking up IXPs in {region}...");
                    candidates = await finder.FindByRegionAsync(region!, infoTypes: infoTypes,
                        excludeCdn: needsHostingFilter, excludeAi: needsAiExclusion, aiOnly: aiOnly, ct: ct);
                }

                // --from: include ASNs from the user's IP list that weren't found by the main search.
                // Applies the same hosting filter as the main search — game companies (Valve),
                // media/CDN networks are still excluded when --type server is active.
                // The hosting filter uses balanced mode (null ipapi.is type + ≥1024 IPs passes),
                // so legitimate cloud providers like Yandex Cloud pass even when ipapi.is is down.
                if (fromAsnList.Count > 0)
                {
                    var foundAsnsSet = new HashSet<uint>(candidates.Select(c => c.Asn));
                    var missing = fromAsnList
                        .Where(a => !foundAsnsSet.Contains(a.Asn))
                        .Take(Math.Max(returnTop, 40))
                        .ToList();
                    if (missing.Count > 0)
                    {
                        ctx.Status($"Supplementing {missing.Count} providers from --from list...");
                        var forced = await finder.FindByAsnListAsync(
                            missing, infoTypes: infoTypes, excludeCdn: needsHostingFilter,
                            excludeAi: needsAiExclusion,
                            localHostingWhitelist: null, ct: ct);
                        candidates = [.. candidates.Concat(forced).DistinctBy(c => c.Asn)];
                    }
                }

                // Country filter: PeeringDB bulk API does not return 'country', so we enrich
                // candidates from ip2asn (which has authoritative ASN→country mappings) before
                // filtering. Applied after all supplements to prevent bypass via --from or local DBs.
                if (countryCodes is { Length: > 0 })
                {
                    if (candidates.Any(c => c.Country == null))
                    {
                        ctx.Status("Resolving countries from ip2asn...");
                        var asnCountry = new Dictionary<uint, string>();
                        foreach (var r in ip2asnRecords)
                            asnCountry.TryAdd(r.Asn, r.Country);
                        candidates = [.. candidates.Select(c =>
                            c.Country == null && asnCountry.TryGetValue(c.Asn, out var cc) && !string.IsNullOrEmpty(cc)
                                ? c with { Country = cc }
                                : c)];
                    }
                    candidates = [.. candidates.Where(c =>
                        countryCodes.Contains(c.Country ?? "", StringComparer.OrdinalIgnoreCase))];
                }

                diagnosticAfterRipe  = candidates.Count;
                diagnosticCandidates = diagnosticAfterRipe;
                if (candidates.Count == 0) return;

                // RIPE Stat country-ASN supplement: recover hosting providers registered in the
                // target countries that PeeringDB's top-N bulk query did not include.
                // Only runs when --country is specified and the search is global (not region-based).
                if (countryCodes is { Length: > 0 } && isGlobal)
                {
                    var foundAsns           = new HashSet<uint>(candidates.Select(c => c.Asn));
                    var updatedCacheEntries = new Dictionary<string, IReadOnlyList<uint>>();
                    var cacheData           = await indexCache.LoadAsync();
                    var supplementPairs     = new List<(uint Asn, int Count)>();

                    foreach (var cc in countryCodes)
                    {
                        IReadOnlyList<uint> countryAsns;
                        if (cacheData != null && cacheData.TryGetValue(cc, out var hit))
                        {
                            countryAsns = hit;
                        }
                        else
                        {
                            ctx.Status($"Fetching ASN registry for {cc} from RIPE Stat...");
                            countryAsns = await ripeClient.GetCountryAsnsAsync(cc, ct);
                            // WR-05: пустой список неотличим от таймаута/сбоя RIPE Stat —
                            // не кэшируем пустоту на 7 дней; подлинно пустая страна
                            // перезапросится в следующем прогоне (это дёшево).
                            if (countryAsns.Count > 0)
                                updatedCacheEntries[cc] = countryAsns;
                        }

                        supplementPairs.AddRange(
                            countryAsns
                                .Where(a => !foundAsns.Contains(a) && !exclusions.NonHostingAsns.Contains(a))
                                .Select(a => (a, 0)));
                    }

                    if (updatedCacheEntries.Count > 0)
                        await indexCache.SaveAsync(updatedCacheEntries);

                    if (supplementPairs.Count > 0)
                    {
                        localHostingAsns ??= await GetLocalHostingAsnsAsync(dataDir);
                        var localWhitelist2 = new HashSet<uint>(localHostingAsns.Select(a => a.Asn));

                        ctx.Status($"Filtering {supplementPairs.Count} country ASNs by local ASN type...");
                        // Локальная карта типов (as.json + bgp.tools) вместо тысяч запросов к ipapi.is.
                        // Whitelist спасает только неизвестных — явный не-hosting вердикт сильнее
                        // (протухшие диапазоны в датасетах: кейс Blizzard/PEER 1).
                        var filteredPairs = supplementPairs
                            .Where(pair =>
                            {
                                var t = asnTypes.TryGetValue(pair.Asn, out var v) ? v : null;
                                if (t is "hosting" or "cloud") return true;
                                return t == null && localWhitelist2.Contains(pair.Asn);
                            })
                            .ToList();
                        if (filteredPairs.Count > 0)
                        {
                            // Build ASN→country map for tagging supplement results.
                            var asnToCountry = new Dictionary<uint, string>();
                            foreach (var cc in countryCodes)
                            {
                                if (cacheData != null && cacheData.TryGetValue(cc, out var c1))
                                    foreach (var asn in c1) asnToCountry.TryAdd(asn, cc);
                                if (updatedCacheEntries.TryGetValue(cc, out var c2))
                                    foreach (var asn in c2) asnToCountry.TryAdd(asn, cc);
                            }

                            ctx.Status($"Enriching {filteredPairs.Count} additional providers from country registry...");
                            var extra = await finder.FindByAsnListAsync(
                                filteredPairs, infoTypes: infoTypes, excludeCdn: needsHostingFilter,
                                excludeAi: needsAiExclusion,
                                localHostingWhitelist: localWhitelist2, ct: ct);

                            extra = [.. extra.Select(c =>
                                c.Country == null && asnToCountry.TryGetValue(c.Asn, out var countryTag)
                                    ? c with { Country = countryTag } : c)];

                            candidates = [.. candidates.Concat(extra).DistinctBy(c => c.Asn)];
                            diagnosticAfterRipe  = candidates.Count;
                            diagnosticCandidates = diagnosticAfterRipe;
                        }
                    }
                }

                // Single choke-point for the vps/dedicated/cloud/server allowlist: all discovery
                // paths (global / region / --from / country-supplement) merge into `candidates`
                // above. Applied once here so the region path — which alone cannot distinguish
                // vps from dedicated/cloud — is covered too (pure allowlist: только ядро).
                candidates = ProviderFinder.ApplyServerAllowlist(
                    candidates, typeFilter, serverProviders);
                if (ProviderFinder.IsServerTypeFilter(typeFilter))
                {
                    diagnosticCandidates = candidates.Count;
                    if (candidates.Count == 0)
                    {
                        AnsiConsole.MarkupLine(
                            $"[yellow]No providers matched --type {Markup.Escape(typeFilter!)}.[/]");
                        return;
                    }
                }

                // CDN pre-filter: apply before scoring so CDN providers (Cloudflare, Akamai, Fastly)
                // aren't crowded out of top-N by large IaaS providers (Microsoft, Amazon) whose IP pools
                // score higher on size metrics. PeeringDB "Content" mixes both types — filter IaaS first.
                if (typeFilter?.ToLowerInvariant() is "cdn" or "content")
                {
                    localHostingAsns ??= await GetLocalHostingAsnsAsync(dataDir);
                    var hostingSetCdn = new HashSet<uint>(localHostingAsns.Select(a => a.Asn));
                    candidates = [.. candidates.Where(c =>
                        !hostingSetCdn.Contains(c.Asn) || exclusions.KnownCdnAsns.Contains(c.Asn))];
                    diagnosticCandidates = candidates.Count;
                    if (candidates.Count == 0) return;
                }

                ctx.Status($"Scoring {diagnosticCandidates} candidates (reputation + ping)...");
                int pingTopN = Math.Max(returnTop * 4, 80);
                var weights  = ScoringWeights.FromName(preset);

                // When --from is active: pin top-coverage providers so they survive the
                // prescore top-N cut in Phase 2 of scoring. Without this, providers with
                // many IPs from the list but few IXP peerings (e.g. Yandex Cloud: 535 IPs,
                // 11 peerings) are eliminated by the peering-weighted prescore before ping.
                IReadOnlySet<uint>? pinnedAsns = null;
                if (coverageMap != null)
                {
                    var candidateAsns = new HashSet<uint>(candidates.Select(c => c.Asn));
                    pinnedAsns = coverageMap
                        .Where(kv => candidateAsns.Contains(kv.Key))
                        .OrderByDescending(kv => kv.Value)
                        .Take(Math.Max(returnTop / 4, 5))
                        .Select(kv => kv.Key)
                        .ToHashSet();
                }

                // WR-06: в режиме --from пользователь явно перечислил провайдеров своим
                // списком IP — жёсткий фильтр abuser_score > 0.75 отключается, как и
                // задокументировано у хард-фильтра в ProviderScorer.
                results = await scorer.ScoreAsync(candidates, maxPingMs, returnTop, pingTopN,
                    strictAbuseFilter: coverageMap == null,
                    weights: weights, pinnedAsns: pinnedAsns, ct: ct);
            });

        int diagnosticAfterScoring = results.Count;

        if (diagnosticPerType != null)
        {
            var perTypeStr = string.Join(", ", diagnosticPerType.Select(p => $"{p.Key}: {p.Value}"));
            AnsiConsole.MarkupLine($"[dim]PeeringDB fetch: {perTypeStr}[/]");
            foreach (var err in diagnosticErrors)
                AnsiConsole.MarkupLine($"[yellow]  ! {Markup.Escape(err)}[/]");
            string cdnFilterNote = diagnosticCandidates != diagnosticAfterRipe
                ? $" → After CDN filter: {diagnosticCandidates}" : "";
            AnsiConsole.MarkupLine($"[dim]Pre-enrichment: {diagnosticPreEnrich} → After RIPE: {diagnosticAfterRipe}{cdnFilterNote} → After scoring: {diagnosticAfterScoring}[/]");
        }
        else
        {
            AnsiConsole.MarkupLine($"[dim]Candidates after enrichment: {diagnosticAfterRipe} | Results after scoring: {diagnosticAfterScoring}[/]");
        }

        if (results.Count == 0)
        {
            if (diagnosticCandidates == 0)
            {
                bool hasErrors   = diagnosticErrors.Count > 0;
                bool isRateLimit = hasErrors && diagnosticErrors.Any(e =>
                    e.Contains("429", StringComparison.Ordinal) ||
                    e.Contains("rate limit", StringComparison.OrdinalIgnoreCase));
                bool isTimeout   = hasErrors && diagnosticErrors.Any(e =>
                    e.Contains("timed out", StringComparison.OrdinalIgnoreCase));

                if (isRateLimit)
                {
                    AnsiConsole.MarkupLine("[yellow]PeeringDB rate limit is blocking results. Get a free API key to raise limits:[/]");
                    AnsiConsole.MarkupLine("  rover --set-key peeringdb=YOUR_KEY  [dim](register free at peeringdb.com)[/]");
                }
                else if (isTimeout)
                {
                    AnsiConsole.MarkupLine("[yellow]PeeringDB requests timed out — check your network connection or try again later.[/]");
                    await CheckPeeringDbConnectivityAsync(peeringDbHttp, ct);
                }
                else if (hasErrors)
                {
                    AnsiConsole.MarkupLine("[yellow]PeeringDB fetch failed — see errors above.[/]");
                    await CheckPeeringDbConnectivityAsync(peeringDbHttp, ct);
                }
                else if (diagnosticPreEnrich == 0 && diagnosticPerType != null)
                {
                    // PeeringDB responded but returned 0 networks
                    AnsiConsole.MarkupLine("[yellow]PeeringDB returned 0 networks for the given filters.[/]");
                    if (typeFilter != null)
                        AnsiConsole.MarkupLine($"[dim]  --type {Markup.Escape(typeFilter)} → {Markup.Escape(string.Join(", ", infoTypes ?? []))}[/]");
                    if (countryDisplay != null)
                        AnsiConsole.MarkupLine($"[dim]  --country {Markup.Escape(countryDisplay)} — try a different country code or remove the filter.[/]");
                    await CheckPeeringDbConnectivityAsync(peeringDbHttp, ct);
                }
                else if (diagnosticPreEnrich > 0)
                {
                    // Had PeeringDB results but RIPE Stat returned no prefixes for any of them
                    AnsiConsole.MarkupLine($"[yellow]{diagnosticPreEnrich} network(s) found in PeeringDB but none had routable IPv4 prefixes in RIPE Stat.[/]");
                    AnsiConsole.MarkupLine("[dim]RIPE Stat may be temporarily unavailable or rate-limiting.[/]");
                    AnsiConsole.MarkupLine("[dim]Try again in a few minutes.[/]");
                }
                else
                {
                    // No diagnostics available — unexpected state, do a live check
                    AnsiConsole.MarkupLine("[yellow]No hosting networks found. Running connectivity check...[/]");
                    await CheckPeeringDbConnectivityAsync(peeringDbHttp, ct);
                }
            }
            else if (maxPingMs.HasValue)
            {
                AnsiConsole.MarkupLine($"[yellow]All {diagnosticCandidates} candidates exceeded --max-ping {maxPingMs} ms or were unreachable.[/]");
                AnsiConsole.MarkupLine("[dim]Try increasing --max-ping or removing it entirely.[/]");
            }
            else
            {
                AnsiConsole.MarkupLine($"[yellow]No providers passed scoring filters ({diagnosticCandidates} candidates scored).[/]");
                if (typeFilter != null)
                    AnsiConsole.MarkupLine($"[dim]  --type {Markup.Escape(typeFilter)} may be filtering too aggressively.[/]");
            }
            return 0; // WR-04: flush выполняется в finally ExecuteAsync
        }

        // --from: annotate results with coverage from the IP list.
        if (coverageMap != null)
        {
            results = [.. results.Select(r => r with {
                CoverageCount = coverageMap.GetValueOrDefault(r.Asn, 0),
                TotalListIps  = totalListIps
            })];
        }

        // Traceroute verification: mark candidates whose ASN appears in the route to traceTo.
        if (!string.IsNullOrWhiteSpace(traceTo))
        {
            AnsiConsole.MarkupLine($"[dim]Tracing route to {Markup.Escape(traceTo)}...[/]");
            try
            {
                var hops     = await new TracerouteService().TraceAsync(traceTo);
                var routeAsns = new HashSet<uint>();
                foreach (var hop in hops)
                {
                    if (hop.IpAddress == null) continue;
                    if (SubnetSearch.Core.Utilities.IpConverter.TryIpToUint(hop.IpAddress, out uint ipUint))
                    {
                        var rec = recoIpIndex.Find(ipUint);
                        if (rec.HasValue) routeAsns.Add(rec.Value.Asn);
                    }
                }
                if (routeAsns.Count > 0)
                    results = [.. results.Select(r => r with { InRoute = routeAsns.Contains(r.Asn) })];
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[yellow]Traceroute failed: {Markup.Escape(ex.Message)}[/]");
            }
        }

        // Apply --sort: re-order results after scoring.
        // "coverage" only makes sense when --from was used (counts IPs from the list per ASN).
        // "latency" falls back to "score" when ICMP is blocked and no latency was measured.
        // Without --from, fall back to "score" to avoid undefined tie-breaking.
        bool noLatencyMeasured = results.Count > 0 && results.All(r => !r.LatencyMs.HasValue);
        string effectiveSort = sortBy?.ToLowerInvariant() switch
        {
            "coverage" when coverageMap == null                        => "score",
            "latency"  when noLatencyMeasured                          => "score",
            { } s => s,
            null    => totalListIps > 0 ? "coverage" : "score",
        };
        if (noLatencyMeasured && sortBy?.ToLowerInvariant() == "latency")
            AnsiConsole.MarkupLine("[yellow]Note: --sort latency has no effect — ICMP blocked, no latency measured. Sorting by score.[/]");

        results = (effectiveSort switch {
            "latency"  => results.OrderBy(r => r.LatencyMs ?? double.MaxValue),
            "rpki"     => results.OrderByDescending(r => r.RpkiScore   ?? 0),
            "size"     => results.OrderByDescending(r => r.TotalIpCount),
            "ip"       => results.OrderByDescending(r => r.TotalIpCount),
            "peering"  => results.OrderByDescending(r => r.PeeringCount ?? 0),
            "upstream" => results.OrderByDescending(r => r.UpstreamCount),
            "coverage" => results.OrderByDescending(r => r.CoverageCount),
            _          => results.OrderByDescending(r => r.Score),
        }).ToList();

        RecommendationRenderer.PrintRecommendations(title, results, abuseIpDb != null, greyNoise != null, traceTo != null);

        return 0; // WR-04: flush выполняется в finally ExecuteAsync
    }

    // ================== HELPERS ==================
    // Extracts hosting ASNs from local datacenter databases (ipcat, cloud-provider, server-ip-addresses).
    // Used to supplement PeeringDB discovery for providers not in PeeringDB's top-N by IX count.
    private static async Task<IReadOnlyList<(uint Asn, int Count)>> GetLocalHostingAsnsAsync(string dataDir)
    {
        var hostingIndex = new HostingRangeIndex();
        await hostingIndex.LoadAsync(dataDir);
        if (hostingIndex.Count == 0) return [];

        var records = await new Ip2AsnLoader().LoadAsync(Path.Combine(dataDir, "ip2asn-v4.tsv.gz"));
        var ipIndex  = new IpRangeIndex(records);

        var asnCounts = new Dictionary<uint, int>();
        foreach (var range in hostingIndex.Ranges)
        {
            var rec = ipIndex.Find(range.StartIp);
            if (rec.HasValue && rec.Value.Asn > 0)
                asnCounts[rec.Value.Asn] = asnCounts.GetValueOrDefault(rec.Value.Asn) + 1;
        }
        return [.. asnCounts.OrderByDescending(kv => kv.Value).Select(kv => (kv.Key, kv.Value))];
    }

    private static async Task CheckPeeringDbConnectivityAsync(HttpClient http, CancellationToken ct)
    {
        try
        {
            // IN-03: собственный 10s-таймаут связан с внешним ct команды — Ctrl+C
            // пользователя отменяет диагностический запрос сразу, а не через 10 секунд.
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            using var resp = await http.GetAsync(
                "https://www.peeringdb.com/api/net?limit=1&status=ok", cts.Token);
            int code = (int)resp.StatusCode;
            if (resp.IsSuccessStatusCode)
                AnsiConsole.MarkupLine($"[dim]PeeringDB connectivity: [green]OK[/] (HTTP {code})[/]");
            else if (code == 429)
            {
                AnsiConsole.MarkupLine($"[yellow]PeeringDB: HTTP 429 — rate limit active.[/]");
                AnsiConsole.MarkupLine("  rover --set-key peeringdb=YOUR_KEY  [dim](register free at peeringdb.com)[/]");
            }
            else
                AnsiConsole.MarkupLine($"[yellow]PeeringDB returned HTTP {code}.[/]");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Отмена пользователя — не таймаут; пробрасываем (flush кэша выполнится
            // в finally ExecuteAsync).
            throw;
        }
        catch (OperationCanceledException)
        {
            AnsiConsole.MarkupLine("[red]PeeringDB: connection timed out (>10s).[/]");
            AnsiConsole.MarkupLine("[dim]Check your internet connection or configure a proxy: rover -r --proxy http://...[/]");
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]PeeringDB unreachable: {Markup.Escape(ex.Message)}[/]");
            AnsiConsole.MarkupLine("[dim]Check your internet connection or configure a proxy: rover -r --proxy http://...[/]");
        }
    }
}
