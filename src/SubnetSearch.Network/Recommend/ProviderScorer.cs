using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Models.Network;
using SubnetSearch.Core.Utilities;
using SubnetSearch.Network.Reputation;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubnetSearch.Network.Recommend;

// Defines relative importance of each scoring component.
// Actual weights are normalized at runtime — missing data (no ping, no RPKI) redistributes
// its weight proportionally across the remaining components rather than penalising the provider.
public record ScoringWeights(
    double Latency,
    double Peering,
    double Reputation,
    double Size,
    double Rpki)
{
    // Default: balanced across all signals.
    public static readonly ScoringWeights Balanced    = new(0.30, 0.20, 0.25, 0.15, 0.10);
    // Performance: low latency and well-peered providers win.
    public static readonly ScoringWeights Performance = new(0.45, 0.30, 0.15, 0.08, 0.02);
    // Security: clean reputation and RPKI-valid prefixes first.
    public static readonly ScoringWeights Security    = new(0.15, 0.10, 0.45, 0.10, 0.20);

    public static ScoringWeights FromName(string? name) => name?.ToLowerInvariant() switch
    {
        "performance" => Performance,
        "security"    => Security,
        _             => Balanced,
    };
}

public class ProviderScorer(
    SpamhausDropClient   spamhaus,
    IpapiIsClient        ipapiIs,
    IIpReputationChecker ipsum,
    PingService          pingService,
    AbuseIpDbClient?     abuseIpDb = null,
    GreyNoiseClient?     greyNoise = null,
    RipeStatCache?       ripeCache = null,
    RipeStatClient?      ripeStat = null)
{
    private sealed class Phase1Candidate(
        ProviderCandidate candidate,
        double ipsumRatio,
        bool rpkiResolved)
    {
        public ProviderCandidate Candidate { get; set; } = candidate;
        public double IpsumRatio { get; } = ipsumRatio;
        public bool RpkiResolved { get; set; } = rpkiResolved;
    }

    // Network-orchestration entry point: fans out live ping / abuse / RPKI probes per candidate and
    // feeds them into the (unit-tested) ComputeScore + cache-serialization helpers. The probing loop
    // itself is integration-tested — excluded so it doesn't skew the business-logic metric.
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    public async Task<IReadOnlyList<ProviderRecommendation>> ScoreAsync(
        IReadOnlyList<ProviderCandidate> candidates,
        int? maxPingMs,
        int returnTop    = 20,
        int pingTopN     = 80,
        int totalListIps = 0,
        bool strictAbuseFilter = true,
        ScoringWeights? weights = null,
        IReadOnlySet<uint>? pinnedAsns = null,
        CancellationToken ct = default)
    {
        await spamhaus.LoadAsync(ct);

        var phase1Candidates = new System.Collections.Concurrent.ConcurrentBag<Phase1Candidate>();

        await Parallel.ForEachAsync(candidates,
            new ParallelOptions { MaxDegreeOfParallelism = 15, CancellationToken = ct },
            (candidate, innerCt) =>
            {
                if (candidate.Prefixes.Count == 0 || spamhaus.IsListed(candidate.Asn))
                    return ValueTask.CompletedTask;

                double ipsumRatio = ComputeIpsumRatio(candidate.Prefixes, ipsum);
                bool rpkiResolved = ripeStat == null || candidate.RpkiScore.HasValue;
                if (!rpkiResolved
                    && ripeStat!.TryGetCachedRpki(
                        candidate.Asn, candidate.Prefixes, out var cachedRpki))
                {
                    candidate = candidate with { RpkiScore = cachedRpki };
                    rpkiResolved = true;
                }
                phase1Candidates.Add(new Phase1Candidate(
                    candidate, ipsumRatio, rpkiResolved));
                return ValueTask.CompletedTask;
            });

        var prepared = phase1Candidates.ToList();
        if (ripeStat != null)
            await ResolveRpkiShortlistAsync(
                prepared, pingTopN, pinnedAsns, weights, ripeStat, ct);

        var phase1 = prepared.Select(entry =>
        {
            double prescore = Prescore(entry.Candidate, entry.IpsumRatio, weights);
            return (c: entry.Candidate, prescore, abuserScore: (double?)null,
                ipsumRatio: entry.IpsumRatio);
        }).ToList();

        // Phase 2: ping top N by prescore.
        // Pinned ASNs (from --from coverage map) are always included regardless of prescore rank,
        // so providers with many IPs but few IXP peerings (e.g. Yandex Cloud) aren't dropped here.
        var orderedPhase1 = phase1.OrderByDescending(x => x.prescore).ThenBy(x => x.c.Asn).ToList();
        List<(ProviderCandidate c, double prescore, double? abuserScore, double ipsumRatio)> topCandidates;
        if (pinnedAsns is { Count: > 0 })
        {
            var pinned    = orderedPhase1.Where(x => pinnedAsns.Contains(x.c.Asn)).ToList();
            var nonPinned = orderedPhase1.Where(x => !pinnedAsns.Contains(x.c.Asn)).Take(pingTopN).ToList();
            topCandidates = [.. pinned.Concat(nonPinned)];
        }
        else
        {
            topCandidates = orderedPhase1.Take(pingTopN).ToList();
        }

        var results = new System.Collections.Concurrent.ConcurrentBag<ProviderRecommendation>();

        // DoP 40: почти всё время кандидата — ожидание ICMP-таймаутов, не CPU.
        await Parallel.ForEachAsync(topCandidates,
            new ParallelOptions { MaxDegreeOfParallelism = 40, CancellationToken = ct },
            async (entry, innerCt) =>
            {
                var (candidate, _, abuserScore, ipsumRatio) = entry;

                // Get the first usable IP from any prefix — for abuser_score lookup only.
                // Does NOT require ICMP response; used regardless of whether ping succeeds.
                string? sampleIp = null;
                foreach (var prefix in candidate.Prefixes.Take(5))
                {
                    sampleIp = GetAnchorIp(prefix);
                    if (sampleIp != null) break;
                }

                // Fetch real abuser_score via IP-level ipapi.is request.
                // abuser_score is absent in ASN-level responses — only available per-IP,
                // but the score itself is an ASN-level attribute → cache-aside per ASN.
                // Non-null scores live 7 days; null (API failure or genuinely absent)
                // only 1 hour so a transient outage isn't frozen into the cache.
                if (sampleIp != null)
                {
                    if (ripeCache != null && ripeCache.TryGet($"abuse_{candidate.Asn}", out var cachedAbuse))
                    {
                        abuserScore = DeserializeAbuseOrNull(cachedAbuse!) ?? abuserScore;
                    }
                    else
                    {
                        var ipInfo = await ipapiIs.GetAsnInfoForIpAsync(sampleIp, innerCt);
                        ripeCache?.Set($"abuse_{candidate.Asn}", SerializeAbuse(ipInfo.AbuserScore),
                            ipInfo.AbuserScore.HasValue ? TimeSpan.FromDays(7) : TimeSpan.FromHours(1));
                        // Prefer IP-level score; keep Phase-1 null only when IP query also returns null.
                        abuserScore = ipInfo.AbuserScore ?? abuserScore;
                    }
                }

                // Hard-filter on now-real abuser_score.
                // In IP-list mode strictAbuseFilter=false — user explicitly wants these providers.
                if (strictAbuseFilter && abuserScore.HasValue && abuserScore.Value > 0.75) return;

                // Try up to 3 prefixes for ICMP ping (latency data — optional).
                // Providers that don't respond to ICMP still appear in results without latency.
                // The winner is the FIRST anchor IP in prefix order that is alive — same
                // selection as the old sequential loop, but unknown IPs are probed in parallel
                // so a fully-silent candidate costs ~1s instead of ~9s.
                var probeIps = new List<string>(3);
                foreach (var prefix in candidate.Prefixes.Take(3))
                {
                    var ip = GetAnchorIp(prefix);
                    if (ip != null && !probeIps.Contains(ip)) probeIps.Add(ip);
                }

                // Cache-aside: pingByIp[ip] == null means "known silent" (negative hit).
                // WR-08: битый JSON — это промах кэша (ключ не добавляется, IP уходит
                // в пробу и перезаписывает битую запись), а не негативный хит.
                var pingByIp = new Dictionary<string, PingStats?>(probeIps.Count);
                foreach (var ip in probeIps)
                {
                    if (ripeCache != null && ripeCache.TryGet($"ping_{ip}", out var cachedJson)
                        && TryDeserializePing(cachedJson!, out var cachedPing))
                        pingByIp[ip] = cachedPing;
                }

                // IPs at or past the first cached-alive one cannot change the outcome — skip them.
                int firstAlive = probeIps.FindIndex(ip => pingByIp.TryGetValue(ip, out var p) && p != null);
                var toProbe = probeIps
                    .Where((ip, i) => !pingByIp.ContainsKey(ip) && (firstAlive < 0 || i < firstAlive))
                    .ToList();

                if (toProbe.Count > 0)
                {
                    await Task.WhenAll(toProbe.Select(async ip =>
                    {
                        // 1-packet discovery: silent hosts cost 1 timeout, not 3.
                        // Full 3-packet measurement (real min/avg/max/loss) only for responders;
                        // a lossy host that answered discovery but not the measurement keeps
                        // the discovery stats rather than being demoted to silent.
                        PingStats? probe;
                        try
                        {
                            var discovery = await pingService.PingAsync(ip, count: 1, cancellationToken: innerCt);
                            probe = discovery == null
                                ? null
                                : await pingService.PingAsync(ip, count: 3, cancellationToken: innerCt) ?? discovery;
                        }
                        catch (OperationCanceledException) when (innerCt.IsCancellationRequested) { throw; }
                        catch
                        {
                            // WR-03: сбой запуска ping-процесса (Win32Exception: нет бинаря
                            // в урезанной системе, и т.п.) не должен ронять весь ScoreAsync
                            // через Task.WhenAll → Parallel.ForEachAsync. Хост трактуется как
                            // silent для этого прогона, но НЕ кэшируется: сбой окружения —
                            // не свойство хоста, замораживать его на 12ч нельзя.
                            lock (pingByIp) pingByIp[ip] = null;
                            return;
                        }
                        // Cache the raw ping result, null included.
                        // 12h TTL: datacenter latency doesn't drift enough within a day to
                        // move the concave latency score, and silent hosts stay silent.
                        ripeCache?.Set($"ping_{ip}", SerializePingOrNull(probe), TimeSpan.FromHours(12));
                        lock (pingByIp) pingByIp[ip] = probe;
                    }));
                }

                string? anchorIp = null;
                PingStats? ping = null;
                foreach (var ip in probeIps)
                {
                    if (pingByIp.TryGetValue(ip, out var p) && p != null)
                    {
                        anchorIp = ip;
                        ping = p;
                        break;
                    }
                }

                double? latencyMs  = ping?.AvgMs;
                double? packetLoss = ping?.PacketLoss;

                // Enforce --max-ping: skip providers that exceed cap or couldn't be pinged at all.
                if (maxPingMs.HasValue && (latencyMs == null || latencyMs > maxPingMs.Value))
                    return;

                // Use sampleIp as display anchor when no prefix responded to ICMP.
                anchorIp ??= sampleIp;
                if (anchorIp == null) return; // no usable prefix at all

                double? abuseIpDbScore = abuseIpDb != null
                    ? await abuseIpDb.GetBlockScoreAsync(candidate.Prefixes[0], innerCt)
                    : null;

                double? greyNoiseRatio = greyNoise != null
                    ? await greyNoise.GetMaliciousRatioAsync(
                        GetSampleIps(candidate.Prefixes[0], 3), innerCt)
                    : null;

                var (score, breakdown) = ComputeScore(
                    latencyMs, packetLoss,
                    candidate.PeeringCount, candidate.Prefixes.Count,
                    abuserScore, ipsumRatio, abuseIpDbScore, greyNoiseRatio,
                    candidate.RpkiScore, candidate.TotalIpCount, weights,
                    upstreamCount: candidate.UpstreamCount);

                string? pricingUrl = PricingPageResolver.Resolve(candidate.Asn, candidate.Name);

                results.Add(new ProviderRecommendation(
                    Asn:            candidate.Asn,
                    Organization:   candidate.Name,
                    Country:        candidate.Country,
                    Website:        candidate.Website,
                    PricingUrl:     pricingUrl,
                    AnchorIp:       anchorIp,
                    LatencyMs:      latencyMs,
                    PacketLoss:     packetLoss,
                    PeeringCount:   candidate.PeeringCount,
                    PrefixCount:    candidate.Prefixes.Count,
                    Score:          score,
                    AbuserScore:    abuserScore,
                    RpkiScore:      candidate.RpkiScore,
                    InSpamhausDrop: false,
                    IxLocations:    candidate.IxLocations,
                    Breakdown:      breakdown,
                    TotalIpCount:    candidate.TotalIpCount,
                    HasIPv6:         candidate.HasIPv6,
                    IPv6PrefixCount: candidate.IPv6PrefixCount,
                    UpstreamCount:   candidate.UpstreamCount,
                    CoverageCount:   candidate.CoverageCount,
                    TotalListIps:    totalListIps
                ));
            });

        // Final selection: pinned ASNs are preferred over non-pinned (they claim returnTop
        // slots first), but the overall result never exceeds returnTop.
        // IN-02: без Take(returnTop) у pinned связка «пин-кап минимум 5» + «pinned минуют
        // общий кап» возвращала при --top 3 --from до 5+ строк.
        var ordered = results.OrderByDescending(r => r.Score).ToList();
        if (pinnedAsns is { Count: > 0 })
        {
            var pinned    = ordered.Where(r => pinnedAsns.Contains(r.Asn)).Take(returnTop).ToList();
            var nonPinned = ordered.Where(r => !pinnedAsns.Contains(r.Asn))
                                   .Take(Math.Max(0, returnTop - pinned.Count)).ToList();
            return [.. pinned.Concat(nonPinned)];
        }
        return [.. ordered.Take(returnTop)];
    }

    private static double Prescore(
        ProviderCandidate candidate,
        double ipsumRatio,
        ScoringWeights? weights,
        double? rpkiScore = null,
        bool overrideRpki = false)
        => ComputeScore(
            latencyMs: null,
            packetLoss: null,
            candidate.PeeringCount,
            candidate.Prefixes.Count,
            abuserScore: null,
            ipsumRatio,
            abuseIpDbScore: null,
            greyNoiseRatio: null,
            overrideRpki ? rpkiScore : candidate.RpkiScore,
            candidate.TotalIpCount,
            weights,
            upstreamCount: candidate.UpstreamCount).Score;

    private static async Task ResolveRpkiShortlistAsync(
        List<Phase1Candidate> entries,
        int pingTopN,
        IReadOnlySet<uint>? pinnedAsns,
        ScoringWeights? weights,
        RipeStatClient ripeStat,
        CancellationToken ct)
    {
        var pinnedMisses = entries
            .Where(entry => !entry.RpkiResolved
                && pinnedAsns?.Contains(entry.Candidate.Asn) == true)
            .ToList();
        await FetchRpkiAsync(pinnedMisses, ripeStat, ct);

        var nonPinned = entries
            .Where(entry => pinnedAsns?.Contains(entry.Candidate.Asn) != true)
            .ToList();
        int target = Math.Min(Math.Max(0, pingTopN), nonPinned.Count);
        if (target == 0) return;

        while (true)
        {
            var unresolved = nonPinned.Where(entry => !entry.RpkiResolved).ToList();
            if (unresolved.Count == 0) return;

            var exact = nonPinned
                .Where(entry => entry.RpkiResolved)
                .Select(entry => (
                    Entry: entry,
                    Score: Prescore(entry.Candidate, entry.IpsumRatio, weights)))
                .OrderByDescending(item => item.Score)
                .ThenBy(item => item.Entry.Candidate.Asn)
                .ToList();

            IEnumerable<Phase1Candidate> eligible = unresolved;
            if (exact.Count >= target)
            {
                var cutoff = exact[target - 1];
                eligible = unresolved.Where(entry =>
                {
                    double upper = Math.Max(
                        Prescore(entry.Candidate, entry.IpsumRatio, weights,
                            rpkiScore: null, overrideRpki: true),
                        Prescore(entry.Candidate, entry.IpsumRatio, weights,
                            rpkiScore: 1.0, overrideRpki: true));
                    return upper > cutoff.Score
                        || upper == cutoff.Score
                           && entry.Candidate.Asn < cutoff.Entry.Candidate.Asn;
                });
            }

            var batch = eligible
                .OrderByDescending(entry => Math.Max(
                    Prescore(entry.Candidate, entry.IpsumRatio, weights,
                        rpkiScore: null, overrideRpki: true),
                    Prescore(entry.Candidate, entry.IpsumRatio, weights,
                        rpkiScore: 1.0, overrideRpki: true)))
                .ThenBy(entry => entry.Candidate.Asn)
                .Take(10)
                .ToList();
            if (batch.Count == 0) return;
            await FetchRpkiAsync(batch, ripeStat, ct);
        }
    }

    private static async Task FetchRpkiAsync(
        IReadOnlyList<Phase1Candidate> entries,
        RipeStatClient ripeStat,
        CancellationToken ct)
    {
        await Parallel.ForEachAsync(entries,
            new ParallelOptions { MaxDegreeOfParallelism = 10, CancellationToken = ct },
            async (entry, innerCt) =>
            {
                double? ratio = null;
                try
                {
                    ratio = await ripeStat.GetRpkiValidityRatioAsync(
                        entry.Candidate.Asn,
                        entry.Candidate.Prefixes,
                        maxSample: 2,
                        ct: innerCt);
                }
                catch (OperationCanceledException) when (innerCt.IsCancellationRequested)
                {
                    throw;
                }
                catch
                {
                }
                entry.Candidate = entry.Candidate with { RpkiScore = ratio };
                entry.RpkiResolved = true;
            });
    }

    // These thresholds map raw metrics to the normalized score range.
    private const double LatencyMs_AtZeroScore    = 200.0; // >200ms → score 0 (latency component)
    private const double PeeringCount_AtMaxScore  = 50.0;  // 50+ peerings → IX score 1
    private const double UpstreamCount_AtMaxScore = 8.0;   // 8+ transit providers → upstream score 1
    private const double IpPool_LogScaleDivisor   = 6.0;   // 10^6 = 1M IPs → size score 1
    private const double Prefix_LogScaleDivisor   = 3.0;   // 10^3 = 1K prefixes → size score 1 (fallback)

    // Returns (totalScore, breakdown).
    // Missing components (no ping, no RPKI) have their weight redistributed proportionally
    // across available components — no penalty for missing data.
    internal static (double Score, ScoreBreakdown Breakdown) ComputeScore(
        double? latencyMs, double? packetLoss,
        int? peeringCount, int prefixCount,
        double? abuserScore, double ipsumRatio,
        double? abuseIpDbScore, double? greyNoiseRatio,
        double? rpkiScore,
        long totalIpCount = 0,
        ScoringWeights? weights = null,
        int upstreamCount = 0)
    {
        weights ??= ScoringWeights.Balanced;

        // Latency: concave decay (quadratic) — slow penalty at low values, steeper above 100ms.
        // 0ms → 1.00 | 50ms → 0.94 | 100ms → 0.75 | 150ms → 0.44 | 200ms → 0.00
        double ls = latencyMs.HasValue
            ? Math.Max(0, 1.0 - Math.Pow(latencyMs.Value / LatencyMs_AtZeroScore, 2.0))
            : 0.0;
        if (latencyMs.HasValue && packetLoss.HasValue && packetLoss.Value > 0)
            ls *= 1.0 - Math.Min(0.5, packetLoss.Value / 100.0);

        // Peering: 70% IX count (global reach) + 30% upstream count (routing resilience).
        // Falls back to pure IX count when upstream data is unavailable (upstreamCount == 0).
        double ixScore = Math.Min(1.0, (peeringCount ?? 0) / PeeringCount_AtMaxScore);
        double ps = upstreamCount > 0
            ? 0.7 * ixScore + 0.3 * Math.Min(1.0, upstreamCount / UpstreamCount_AtMaxScore)
            : ixScore;

        // Size: log scale (1K→0.17, 100K→0.83, 1M→1.0). Falls back to prefix count.
        double ss = totalIpCount > 0
            ? Math.Min(1.0, Math.Log10(totalIpCount + 1) / IpPool_LogScaleDivisor)
            : Math.Min(1.0, Math.Log10(prefixCount + 1) / Prefix_LogScaleDivisor);

        // Reputation: combined from all available sources, inverted.
        var abuseSamples = new List<double> { ipsumRatio };
        if (abuserScore.HasValue)    abuseSamples.Add(abuserScore.Value);
        // abuseIpDbScore is 0-100 (abuseConfidenceScore percent); divide by 100 to normalize to [0,1].
        if (abuseIpDbScore.HasValue) abuseSamples.Add(abuseIpDbScore.Value / 100.0);
        if (greyNoiseRatio.HasValue) abuseSamples.Add(greyNoiseRatio.Value);
        double abs = 1.0 - Math.Min(1.0, abuseSamples.Average());

        // Build weighted sum including only components with available data.
        // Missing latency or RPKI does NOT reduce the score — weight redistributes to others.
        var components = new List<(double value, double weight)>
        {
            (ps,  weights.Peering),
            (abs, weights.Reputation),
            (ss,  weights.Size),
        };
        if (latencyMs.HasValue) components.Add((ls, weights.Latency));
        if (rpkiScore.HasValue) components.Add((rpkiScore.Value, weights.Rpki));

        double totalW = components.Sum(c => c.weight);
        double score  = components.Sum(c => c.value * c.weight / totalW);

        return (score, new ScoreBreakdown(ls, ps, abs, ss, rpkiScore));
    }

    // Wrapper so a null PingStats (silent host) round-trips unambiguously through the cache.
    private record PingCacheData(
        [property: JsonPropertyName("p")] PingStats? Ping);

    internal static string SerializePingOrNull(PingStats? p)
        => JsonSerializer.Serialize(new PingCacheData(p));

    // Corrupt JSON is treated as "no cached data" (swallow-and-fallback convention).
    internal static PingStats? DeserializePingOrNull(string json)
        => TryDeserializePing(json, out var stats) ? stats : null;

    // WR-08: Try-паттерн дизамбигуирует «битый JSON» и «настоящий негативный хит»:
    // false → JsonException (call-site трактует как промах кэша: IP уходит в пробу
    // и перезаписывает битую запись); true + stats == null → хост молчит (не пинговать).
    internal static bool TryDeserializePing(string json, out PingStats? stats)
    {
        try { stats = JsonSerializer.Deserialize<PingCacheData>(json)?.Ping; return true; }
        catch (JsonException) { stats = null; return false; }
    }

    // Wrapper so a null abuser_score round-trips unambiguously through the cache.
    private record AbuseCacheData(
        [property: JsonPropertyName("a")] double? Score);

    internal static string SerializeAbuse(double? score)
        => JsonSerializer.Serialize(new AbuseCacheData(score));

    // Corrupt JSON is treated as "no data" (swallow-and-fallback convention).
    internal static double? DeserializeAbuseOrNull(string json)
    {
        try { return JsonSerializer.Deserialize<AbuseCacheData>(json)?.Score; }
        catch (JsonException) { return null; }
    }

    internal static string? GetAnchorIp(string cidr)
    {
        try
        {
            var slash    = cidr.IndexOf('/');
            var hostPart = slash < 0 ? cidr : cidr[..slash];
            var octets   = hostPart.Split('.').Select(int.Parse).ToArray();
            if (octets.Length != 4) return null;
            int prefix = slash < 0 ? 32 : int.Parse(cidr[(slash + 1)..]);
            // /32 = single host; /31 = two usable hosts (RFC 3021) — use base address directly.
            if (prefix >= 31) return hostPart;
            if (octets[3] >= 254) return null;
            octets[3]++;
            return string.Join(".", octets);
        }
        catch { return null; }
    }

    internal static IEnumerable<string> GetSampleIps(string cidr, int count)
    {
        var anchor = GetAnchorIp(cidr);
        if (anchor == null) yield break;
        var parts = anchor.Split('.').Select(int.Parse).ToArray();
        for (int i = 0; i < count; i++)
        {
            if (parts[3] > 254) yield break;
            yield return string.Join(".", parts);
            parts[3]++;
        }
    }

    private static double ComputeIpsumRatio(IReadOnlyList<string> prefixes, IIpReputationChecker ipsum)
    {
        const int maxSamples = 300;
        int sampled = 0, flagged = 0;
        try
        {
            // Distribute samples evenly across all prefixes.
            // For each prefix sample IPs at a regular stride to cover the full range.
            int perPrefix = Math.Max(1, maxSamples / Math.Max(1, prefixes.Count));
            foreach (var cidr in prefixes)
            {
                if (sampled >= maxSamples) break;
                if (!IpConverter.TryParseCidr(cidr, out var start, out var end)) continue;
                long size = (long)end - start + 1;
                if (size <= 0) continue;
                long step = Math.Max(1, size / perPrefix);
                for (long ip = start; ip <= end && sampled < maxSamples; ip += step)
                {
                    if ((ipsum.Check((uint)ip) ?? 0) > 0) flagged++;
                    sampled++;
                }
            }
        }
        catch { }
        return sampled > 0 ? (double)flagged / sampled : 0.0;
    }
}
