using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Network;
using SubnetSearch.Core.Utilities;
using SubnetSearch.Network.Reputation;

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
    IIpRangeIndex?       ipIndex   = null)
{
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

        // Phase 1: cheap signals — reputation, RPKI (already fetched by ProviderFinder).
        var phase1 = new System.Collections.Concurrent.ConcurrentBag<(ProviderCandidate c, double prescore, double? abuserScore, double ipsumRatio)>();

        await Parallel.ForEachAsync(candidates,
            new ParallelOptions { MaxDegreeOfParallelism = 15, CancellationToken = ct },
            async (candidate, innerCt) =>
            {
                if (candidate.Prefixes.Count == 0) return;
                if (spamhaus.IsListed(candidate.Asn)) return;

                var abuserScore   = await ipapiIs.GetAbuserScoreAsync(candidate.Asn, innerCt);

                // Hard-filter: skip providers with very high abuse rate.
                // In IP-list mode strictAbuseFilter=false — user explicitly wants these providers.
                if (strictAbuseFilter && abuserScore.HasValue && abuserScore.Value > 0.75) return;

                double ipsumRatio = ComputeIpsumRatio(candidate.Prefixes[0], ipsum);
                double prescore   = ComputeScore(
                    latencyMs: null, packetLoss: null,
                    candidate.PeeringCount, candidate.Prefixes.Count,
                    abuserScore, ipsumRatio, null, null,
                    candidate.RpkiScore, candidate.TotalIpCount, weights).Score;

                phase1.Add((candidate, prescore, abuserScore, ipsumRatio));
            });

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

        await Parallel.ForEachAsync(topCandidates,
            new ParallelOptions { MaxDegreeOfParallelism = 20, CancellationToken = ct },
            async (entry, innerCt) =>
            {
                var (candidate, _, abuserScore, ipsumRatio) = entry;
                string? anchorIp = GetAnchorIp(candidate.Prefixes[0]);
                if (anchorIp == null) return;

                var ping = await pingService.PingAsync(anchorIp, count: 3, cancellationToken: innerCt);

                // TCP RST timing is valid but may hit CDN edge — try traceroute for real DC latency.
                if (ping?.IsTcp == true && ipIndex != null)
                {
                    var trPing = await pingService.PingViaTracerouteAsync(anchorIp, candidate.Asn, ipIndex, innerCt);
                    if (trPing != null) ping = trPing;
                }

                double? latencyMs  = ping?.AvgMs;
                double? packetLoss = ping?.PacketLoss;

                if (maxPingMs.HasValue && (latencyMs == null || latencyMs > maxPingMs.Value))
                    return;

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
                    candidate.RpkiScore, candidate.TotalIpCount, weights);

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

        // Final selection: pinned ASNs are always included (they bypass the returnTop cap on non-pinned).
        var ordered = results.OrderByDescending(r => r.Score).ToList();
        if (pinnedAsns is { Count: > 0 })
        {
            var pinned    = ordered.Where(r => pinnedAsns.Contains(r.Asn)).ToList();
            var nonPinned = ordered.Where(r => !pinnedAsns.Contains(r.Asn))
                                   .Take(Math.Max(0, returnTop - pinned.Count)).ToList();
            return [.. pinned.Concat(nonPinned)];
        }
        return [.. ordered.Take(returnTop)];
    }

    // Scoring thresholds — tune these to adjust how the scoring function maps raw metrics to [0,1].
    private const double LatencyMs_AtZeroScore    = 200.0; // >200ms → score 0 (latency component)
    private const double PeeringCount_AtMaxScore  = 50.0;  // 50+ peerings → score 1
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
        ScoringWeights? weights = null)
    {
        weights ??= ScoringWeights.Balanced;

        // Latency: 0ms → 1.0, 200ms → 0.0; penalised by packet loss.
        double ls = latencyMs.HasValue ? Math.Max(0, 1.0 - latencyMs.Value / LatencyMs_AtZeroScore) : 0.0;
        if (latencyMs.HasValue && packetLoss.HasValue && packetLoss.Value > 0)
            ls *= 1.0 - Math.Min(0.5, packetLoss.Value / 100.0);

        // Peerings: 0 → 0.0, 50+ → 1.0
        double ps = Math.Min(1.0, (peeringCount ?? 0) / PeeringCount_AtMaxScore);

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

    private static double ComputeIpsumRatio(string cidr, IIpReputationChecker ipsum)
    {
        try
        {
            if (!IpConverter.TryParseCidr(cidr, out var start, out var end)) return 0.0;
            long total   = Math.Min((long)end - start + 1, 50);
            if (total <= 0) return 0.0;
            long flagged = 0;
            for (long ip = start; ip < (long)start + total; ip++)
                if ((ipsum.Check((uint)ip) ?? 0) > 0) flagged++;
            return (double)flagged / total;
        }
        catch { return 0.0; }
    }
}
