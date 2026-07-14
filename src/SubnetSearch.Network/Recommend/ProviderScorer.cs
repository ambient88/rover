using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Models.Network;
using SubnetSearch.Core.Utilities;
using SubnetSearch.Network.Reputation;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubnetSearch.Network.Recommend;

// Defines relative importance of each scoring component.
// Weights are normalized at runtime. Missing ping or RPKI data redistributes
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
    private readonly SemaphoreSlim _pingThrottle = new(16, 16);

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
    // feeds them into the tested ComputeScore and cache serialization helpers. The probing loop
    // itself is covered by integration tests and excluded from the business logic metric.
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
        TimeSpan? networkBudget = null,
        CancellationToken ct = default)
    {
        var networkClock = System.Diagnostics.Stopwatch.StartNew();
        using (var spamhausBudget = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            var spamhausTime = RemainingNetworkTime(
                networkBudget, networkClock, TimeSpan.FromSeconds(2));
            if (spamhausTime > TimeSpan.Zero)
                spamhausBudget.CancelAfter(spamhausTime);
            else
                spamhausBudget.Cancel();
            try
            {
                await spamhaus.LoadAsync(spamhausBudget.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
            }
        }

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
        {
            using var rpkiBudget = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var rpkiTime = RemainingNetworkTime(networkBudget, networkClock, TimeSpan.FromSeconds(1));
            if (rpkiTime > TimeSpan.Zero)
                rpkiBudget.CancelAfter(rpkiTime);
            else
                rpkiBudget.Cancel();
            try
            {
                await ResolveRpkiShortlistAsync(
                    prepared, pingTopN, pinnedAsns, weights, ripeStat, rpkiBudget.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
            }
        }

        var phase1 = prepared.Select(entry =>
        {
            double prescore = Prescore(entry.Candidate, entry.IpsumRatio, weights);
            return (c: entry.Candidate, prescore, abuserScore: (double?)null,
                ipsumRatio: entry.IpsumRatio);
        }).ToList();

        // Ping the top candidates by prescore.
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

        var liveAbuseAsns = new HashSet<uint>(topCandidates
            .Take(Math.Min(topCandidates.Count, Math.Max(returnTop, 10)))
            .Select(entry => entry.c.Asn));

        var results = new System.Collections.Concurrent.ConcurrentBag<ProviderRecommendation>();
        var rejectedAsns = new System.Collections.Concurrent.ConcurrentDictionary<uint, byte>();

        using var liveBudget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var liveTime = RemainingNetworkTime(networkBudget, networkClock, TimeSpan.FromSeconds(4));
        if (liveTime > TimeSpan.Zero)
            liveBudget.CancelAfter(liveTime);
        else
            liveBudget.Cancel();
        try
        {
            await Parallel.ForEachAsync(topCandidates,
            new ParallelOptions { MaxDegreeOfParallelism = 40, CancellationToken = liveBudget.Token },
            async (entry, innerCt) =>
            {
                var (candidate, _, abuserScore, ipsumRatio) = entry;

                // Get the first usable IP from any prefix for the abuser_score lookup.
                // This lookup does not require an ICMP response and runs even when ping fails.
                string? sampleIp = null;
                foreach (var prefix in candidate.Prefixes.Take(5))
                {
                    sampleIp = GetAnchorIp(prefix);
                    if (sampleIp != null) break;
                }

                // Fetch real abuser_score via IP-level ipapi.is request.
                // abuser_score is absent from ASN-level responses and only available per IP,
                // but the score is an ASN-level attribute, so cache it per ASN.
                // Non-null scores live 7 days; null (API failure or genuinely absent)
                // only 1 hour so a transient outage isn't frozen into the cache.
                if (sampleIp != null)
                {
                    if (ripeCache != null && ripeCache.TryGet($"abuse_{candidate.Asn}", out var cachedAbuse))
                    {
                        abuserScore = DeserializeAbuseOrNull(cachedAbuse!) ?? abuserScore;
                    }
                    else if (liveAbuseAsns.Contains(candidate.Asn))
                    {
                        var ipInfo = await ipapiIs.GetAsnInfoForIpAsync(sampleIp, innerCt);
                        ripeCache?.Set($"abuse_{candidate.Asn}", SerializeAbuse(ipInfo.AbuserScore),
                            ipInfo.AbuserScore.HasValue ? TimeSpan.FromDays(7) : TimeSpan.FromHours(1));
                        // Prefer the IP-level score and keep null only when the IP query also returns null.
                        abuserScore = ipInfo.AbuserScore ?? abuserScore;
                    }
                }

                // Hard-filter on now-real abuser_score.
                // IP-list mode disables the strict abuse filter because the user requested these providers.
                if (strictAbuseFilter && abuserScore.HasValue && abuserScore.Value > 0.75)
                {
                    rejectedAsns.TryAdd(candidate.Asn, 0);
                    return;
                }

                // Try up to three prefixes for optional ICMP latency data.
                // Providers that don't respond to ICMP still appear in results without latency.
                // Use the first responsive anchor IP in prefix order. This matches the
                // selection as the old sequential loop, but unknown IPs are probed in parallel
                // so a fully-silent candidate costs ~1s instead of ~9s.
                var probeIps = new List<string>(3);
                foreach (var prefix in candidate.Prefixes.Take(3))
                {
                    var ip = GetAnchorIp(prefix);
                    if (ip != null && !probeIps.Contains(ip)) probeIps.Add(ip);
                }

                // A null pingByIp value marks a known silent host.
                // WR-08: corrupt JSON is a cache miss (the key is not added, the IP goes
                // to a probe and overwrites the corrupt entry), not a negative hit.
                var pingByIp = new Dictionary<string, PingStats?>(probeIps.Count);
                foreach (var ip in probeIps)
                {
                    if (ripeCache != null && ripeCache.TryGet($"ping_{ip}", out var cachedJson)
                        && TryDeserializePing(cachedJson!, out var cachedPing))
                        pingByIp[ip] = cachedPing;
                }

                // Skip IPs at or after the first cached responsive address because they cannot change the result.
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
                            var discovery = await PingWithThrottleAsync(ip, 1, innerCt);
                            probe = discovery == null
                                ? null
                                : await PingWithThrottleAsync(ip, 3, innerCt) ?? discovery;
                        }
                        catch (OperationCanceledException) when (innerCt.IsCancellationRequested) { throw; }
                        catch
                        {
                            // WR-03: a failure to start the ping process (Win32Exception: no binary
                            // on a stripped-down system, etc.) must not bring down the whole ScoreAsync
                            // through Task.WhenAll and Parallel.ForEachAsync. Treat the host as
                            // silent for this run without caching the environment failure.
                            // not a property of the host, so it must not be frozen for 12h.
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
                {
                    rejectedAsns.TryAdd(candidate.Asn, 0);
                    return;
                }

                // Use sampleIp as display anchor when no prefix responded to ICMP.
                anchorIp ??= sampleIp;
                if (anchorIp == null)
                {
                    rejectedAsns.TryAdd(candidate.Asn, 0);
                    return;
                }

                Task<double?> abuseIpDbTask = abuseIpDb != null
                    ? abuseIpDb.GetBlockScoreAsync(candidate.Prefixes[0], innerCt)
                    : Task.FromResult<double?>(null);
                Task<double?> greyNoiseTask = greyNoise != null
                    ? greyNoise.GetMaliciousRatioAsync(
                        GetSampleIps(candidate.Prefixes[0], 3), innerCt)
                    : Task.FromResult<double?>(null);
                await Task.WhenAll(abuseIpDbTask, greyNoiseTask);
                double? abuseIpDbScore = await abuseIpDbTask;
                double? greyNoiseRatio = await greyNoiseTask;

                var (score, breakdown) = ComputeScore(
                    latencyMs, packetLoss,
                    candidate.PeeringCount, candidate.Prefixes.Count,
                    abuserScore, ipsumRatio, abuseIpDbScore, greyNoiseRatio,
                    candidate.RpkiScore, candidate.TotalIpCount, weights,
                    upstreamCount: candidate.UpstreamCount);

                results.Add(CreateRecommendation(
                    candidate, anchorIp, latencyMs, packetLoss, score, abuserScore,
                    breakdown, totalListIps));
            });
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
        }

        // Keep locally scored candidates when optional probes run out of time.
        // A max-ping filter still requires a completed ping and does not use this fallback.
        if (!maxPingMs.HasValue)
        {
            var completedAsns = new HashSet<uint>(results.Select(result => result.Asn));
            foreach (var entry in topCandidates)
            {
                var candidate = entry.c;
                if (completedAsns.Contains(candidate.Asn) || rejectedAsns.ContainsKey(candidate.Asn))
                    continue;

                string? anchorIp = candidate.Prefixes.Select(GetAnchorIp).FirstOrDefault(ip => ip != null);
                if (anchorIp == null) continue;

                double? abuserScore = entry.abuserScore;
                if (ripeCache != null
                    && ripeCache.TryGet($"abuse_{candidate.Asn}", out var cachedAbuse))
                    abuserScore = DeserializeAbuseOrNull(cachedAbuse!) ?? abuserScore;
                if (strictAbuseFilter && abuserScore is > 0.75) continue;

                var (score, breakdown) = ComputeScore(
                    latencyMs: null, packetLoss: null,
                    candidate.PeeringCount, candidate.Prefixes.Count,
                    abuserScore, entry.ipsumRatio,
                    abuseIpDbScore: null, greyNoiseRatio: null,
                    candidate.RpkiScore, candidate.TotalIpCount, weights,
                    upstreamCount: candidate.UpstreamCount);
                results.Add(CreateRecommendation(
                    candidate, anchorIp, null, null, score, abuserScore,
                    breakdown, totalListIps));
                completedAsns.Add(candidate.Asn);
            }
        }

        // Final selection: pinned ASNs are preferred over non-pinned (they claim returnTop
        // slots first), but the overall result never exceeds returnTop.
        // IN-02: without Take(returnTop) on pinned, the "pin cap at least 5" plus "pinned bypass
        // the shared cap combination returned more rows than requested by --top.
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

    internal static TimeSpan RemainingNetworkTime(
        TimeSpan? totalBudget,
        System.Diagnostics.Stopwatch clock,
        TimeSpan phaseLimit)
    {
        if (!totalBudget.HasValue) return phaseLimit;
        var remaining = totalBudget.Value - clock.Elapsed;
        if (remaining <= TimeSpan.Zero) return TimeSpan.Zero;
        return remaining < phaseLimit ? remaining : phaseLimit;
    }

    private static ProviderRecommendation CreateRecommendation(
        ProviderCandidate candidate,
        string anchorIp,
        double? latencyMs,
        double? packetLoss,
        double score,
        double? abuserScore,
        ScoreBreakdown breakdown,
        int totalListIps)
        => new(
            Asn:            candidate.Asn,
            Organization:   candidate.Name,
            Country:        candidate.Country,
            Website:        candidate.Website,
            PricingUrl:     PricingPageResolver.Resolve(candidate.Asn, candidate.Name),
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
            TotalListIps:    totalListIps);

    // Live ICMP wrapper used only by the excluded ScoreAsync orchestration loop;
    // integration-scope for the same reason.
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    private async Task<PingStats?> PingWithThrottleAsync(
        string ip,
        int count,
        CancellationToken ct)
    {
        await _pingThrottle.WaitAsync(ct);
        try
        {
            return await pingService.PingAsync(ip, count, ct);
        }
        finally
        {
            _pingThrottle.Release();
        }
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

    // Live RIPE Stat fan-out used only by the excluded ScoreAsync orchestration loop;
    // integration-scope for the same reason.
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
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
    private const double LatencyMs_AtZeroScore    = 200.0; // Latency at or above 200 ms scores zero.
    private const double PeeringCount_AtMaxScore  = 50.0;  // Fifty peerings produce the maximum IX score.
    private const double UpstreamCount_AtMaxScore = 8.0;   // Eight upstreams produce the maximum upstream score.
    private const double IpPool_LogScaleDivisor   = 6.0;   // One million IPs produce the maximum size score.
    private const double Prefix_LogScaleDivisor   = 3.0;   // One thousand prefixes produce the fallback maximum.

    // Returns (totalScore, breakdown).
    // Missing components (no ping, no RPKI) have their weight redistributed proportionally
    // across available components without penalizing missing data.
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

        // Latency uses quadratic decay with a steeper penalty above 100 ms.
        // Scores are 1.00 at 0 ms, 0.94 at 50 ms, 0.75 at 100 ms, 0.44 at 150 ms, and 0 at 200 ms.
        double ls = latencyMs.HasValue
            ? Math.Max(0, 1.0 - Math.Pow(latencyMs.Value / LatencyMs_AtZeroScore, 2.0))
            : 0.0;
        if (latencyMs.HasValue && packetLoss.HasValue && packetLoss.Value > 0)
            ls *= 1.0 - Math.Min(0.5, packetLoss.Value / 100.0);

        // Peering combines 70 percent IX count with 30 percent upstream count.
        // Without upstream data, the IX count supplies the full component.
        bool hasPeeringData = peeringCount.HasValue || upstreamCount > 0;
        double ixScore = Math.Min(1.0, (peeringCount ?? 0) / PeeringCount_AtMaxScore);
        double upstreamScore = Math.Min(1.0, upstreamCount / UpstreamCount_AtMaxScore);
        double ps = (peeringCount.HasValue, upstreamCount > 0) switch
        {
            (true, true) => 0.7 * ixScore + 0.3 * upstreamScore,
            (true, false) => ixScore,
            (false, true) => upstreamScore,
            _ => 0.0,
        };

        // Size uses a log scale. It scores about 0.50 at 1K IPs, 0.83 at 100K IPs, and 1.0 at 1M IPs.
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
        // Missing latency or RPKI data redistributes its weight instead of reducing the score.
        var components = new List<(double value, double weight)>
        {
            (abs, weights.Reputation),
            (ss,  weights.Size),
        };
        if (hasPeeringData) components.Add((ps, weights.Peering));
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

    // WR-08: the Try pattern disambiguates "corrupt JSON" from "a real negative hit":
    // False reports corrupt JSON as a cache miss so a live probe can replace it.
    // True with null stats identifies a known silent host that should not be pinged again.
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
            // Use the base address directly for a single-host /32 or a two-host /31 network.
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

    internal static double ComputeIpsumRatio(IReadOnlyList<string> prefixes, IIpReputationChecker ipsum)
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
