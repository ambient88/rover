using FluentAssertions;
using System.Net;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Network;
using SubnetSearch.Network.Recommend;
using SubnetSearch.Network.Reputation;

namespace SubnetSearch.Tests;

public class ProviderScorerTests
{
    private sealed class CleanReputation : IIpReputationChecker
    {
        public int? Check(uint ipInt) => 0;
    }

    private static double Score(double? lat, int? peering, int prefixes,
        double? abuser, double ipsum,
        double? abuseIpDb = null, double? greyNoise = null, double? rpki = null)
        => ProviderScorer.ComputeScore(lat, null, peering, prefixes, abuser, ipsum, abuseIpDb, greyNoise, rpki).Score;

    [Fact]
    public void ComputeScore_PerfectProvider_ScoresNearOne()
        => Score(1, 100, 1000, 0.0, 0.0, rpki: 1.0).Should().BeGreaterThan(0.85);

    [Fact]
    public void ComputeScore_HighLatency_ReducesScore()
    {
        var low  = Score(5,   10, 10, 0.0, 0.0);
        var high = Score(190, 10, 10, 0.0, 0.0);
        low.Should().BeGreaterThan(high);
    }

    [Fact]
    public void ComputeScore_HighAbuseRatio_ReducesScore()
    {
        var clean = Score(10, 10, 10, 0.0, 0.0);
        var dirty = Score(10, 10, 10, 0.9, 0.9);
        clean.Should().BeGreaterThan(dirty);
    }

    [Fact]
    public void ComputeScore_UnreachableHost_HasZeroLatencyContribution()
    {
        var reachable   = Score(10,   10, 10, 0.0, 0.0);
        var unreachable = Score(null, 10, 10, 0.0, 0.0);
        reachable.Should().BeGreaterThan(unreachable);
    }

    [Fact]
    public void ComputeScore_AlwaysBetweenZeroAndOne()
        => Score(50, 25, 100, 0.3, 0.1, 20.0, 0.1, 0.8).Should().BeInRange(0.0, 1.0);

    [Fact]
    public void ComputeScore_PacketLoss_ReducesLatencyContribution()
    {
        var noLoss   = ProviderScorer.ComputeScore(10, 0.0,  10, 10, 0.0, 0.0, null, null, null).Score;
        var withLoss = ProviderScorer.ComputeScore(10, 50.0, 10, 10, 0.0, 0.0, null, null, null).Score;
        noLoss.Should().BeGreaterThan(withLoss);
    }

    [Fact]
    public void ComputeScore_RpkiBoostsScore()
    {
        var noRpki   = Score(10, 10, 10, 0.0, 0.0, rpki: null);
        var fullRpki = Score(10, 10, 10, 0.0, 0.0, rpki: 1.0);
        fullRpki.Should().BeGreaterThanOrEqualTo(noRpki);
    }

    [Fact]
    public void ComputeScore_ReturnsBreakdown()
    {
        var (_, breakdown) = ProviderScorer.ComputeScore(10, null, 20, 50, 0.1, 0.0, null, null, 0.9);
        breakdown.Should().NotBeNull();
        breakdown!.Latency.Should().BeInRange(0.0, 1.0);
        breakdown.Rpki.Should().Be(0.9);
    }

    [Theory]
    [InlineData("10.0.0.0/8",  "10.0.0.1")]
    [InlineData("8.8.8.0/24",  "8.8.8.1")]
    [InlineData("1.2.3.0/30",  "1.2.3.1")]
    public void GetAnchorIp_ReturnsFirstHostAddress(string cidr, string expected)
        => ProviderScorer.GetAnchorIp(cidr).Should().Be(expected);

    [Fact]
    public void GetAnchorIp_ReturnsNullForUnparsableOctets()
        => ProviderScorer.GetAnchorIp("abc.def.ghi.jkl/24").Should().BeNull();

    [Fact]
    public void GetSampleIps_ReturnsConsecutiveAddresses()
    {
        var ips = ProviderScorer.GetSampleIps("192.168.1.0/24", 3).ToList();
        ips.Should().Equal("192.168.1.1", "192.168.1.2", "192.168.1.3");
    }

    // Ping cache serialization and RipeStatCache round trips.

    [Fact]
    public void SerializePingOrNull_RoundTripsPopulatedStats() // Positive result.
    {
        var stats = new SubnetSearch.Core.Models.Classification.PingStats(1.5, 2.5, 4.0, 33);
        var json  = ProviderScorer.SerializePingOrNull(stats);
        var back  = ProviderScorer.DeserializePingOrNull(json);
        back.Should().NotBeNull();
        back!.MinMs.Should().Be(1.5);
        back.AvgMs.Should().Be(2.5);
        back.MaxMs.Should().Be(4.0);
        back.PacketLoss.Should().Be(33);
    }

    [Fact]
    public void SerializePingOrNull_RoundTripsNull() // Negative result for a silent host.
    {
        var json = ProviderScorer.SerializePingOrNull(null);
        ProviderScorer.DeserializePingOrNull(json).Should().BeNull();
    }

    [Fact]
    public void PingCache_HitPath_ReconstructsStatsFromRealCache() // Cache hit without a new ping process.
    {
        var dir = Path.Combine(Path.GetTempPath(), $"scorer-cache-{Guid.NewGuid():N}");
        try
        {
            var cache = new RipeStatCache(dir);
            var stats = new SubnetSearch.Core.Models.Classification.PingStats(1.0, 2.0, 3.0, 0);
            cache.Set("ping_8.8.8.1", ProviderScorer.SerializePingOrNull(stats), TimeSpan.FromMinutes(10));

            cache.TryGet("ping_8.8.8.1", out var json).Should().BeTrue();
            var back = ProviderScorer.DeserializePingOrNull(json!);
            back.Should().NotBeNull();
            back!.AvgMs.Should().Be(2.0);
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void PingCache_NegativeHit_SignalsSkipWithoutRePing() // Cached silent host.
    {
        var dir = Path.Combine(Path.GetTempPath(), $"scorer-cache-{Guid.NewGuid():N}");
        try
        {
            var cache = new RipeStatCache(dir);
            cache.Set("ping_10.0.0.1", ProviderScorer.SerializePingOrNull(null), TimeSpan.FromMinutes(10));

            // A cached null value means the host is silent and should not be pinged again.
            cache.TryGet("ping_10.0.0.1", out var json).Should().BeTrue();
            ProviderScorer.DeserializePingOrNull(json!).Should().BeNull();
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void DeserializePingOrNull_ToleratesCorruptJson()
        => ProviderScorer.DeserializePingOrNull("{ not json ]").Should().BeNull();

    // Corrupt JSON is distinct from an authoritative negative cache hit.

    [Fact]
    public void TryDeserializePing_CorruptJson_SignalsCacheMiss() // False sends the IP to a live probe.
    {
        ProviderScorer.TryDeserializePing("{ not json ]", out var stats).Should().BeFalse();
        stats.Should().BeNull();
    }

    [Fact]
    public void TryDeserializePing_NegativeHit_SignalsKnownSilent() // True with null identifies a silent host.
    {
        var json = ProviderScorer.SerializePingOrNull(null);
        ProviderScorer.TryDeserializePing(json, out var stats).Should().BeTrue();
        stats.Should().BeNull();
    }

    [Fact]
    public void TryDeserializePing_PositiveHit_ReturnsStats() // True with stats returns a responsive cached host.
    {
        var json = ProviderScorer.SerializePingOrNull(
            new SubnetSearch.Core.Models.Classification.PingStats(1.0, 2.0, 3.0, 0));
        ProviderScorer.TryDeserializePing(json, out var stats).Should().BeTrue();
        stats.Should().NotBeNull();
        stats!.AvgMs.Should().Be(2.0);
    }

    // ipapi.is abuser_score values are cached by ASN.

    [Fact]
    public void SerializeAbuse_RoundTripsScore() // Positive result.
    {
        var json = ProviderScorer.SerializeAbuse(0.0042);
        ProviderScorer.DeserializeAbuseOrNull(json).Should().Be(0.0042);
    }

    [Fact]
    public void SerializeAbuse_RoundTripsNull() // Negative result for missing data or an API failure.
    {
        var json = ProviderScorer.SerializeAbuse(null);
        ProviderScorer.DeserializeAbuseOrNull(json).Should().BeNull();
    }

    [Fact]
    public void AbuseCache_HitPath_ReconstructsScoreFromRealCache() // Cache hit without an HTTP request.
    {
        var dir = Path.Combine(Path.GetTempPath(), $"scorer-cache-{Guid.NewGuid():N}");
        try
        {
            var cache = new RipeStatCache(dir);
            cache.Set("abuse_21859", ProviderScorer.SerializeAbuse(0.13), TimeSpan.FromDays(7));

            cache.TryGet("abuse_21859", out var json).Should().BeTrue();
            ProviderScorer.DeserializeAbuseOrNull(json!).Should().Be(0.13);
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void DeserializeAbuseOrNull_ToleratesCorruptJson()
        => ProviderScorer.DeserializeAbuseOrNull("{ not json ]").Should().BeNull();

    [Fact]
    public async Task ScoreAsync_ColdRpkiFetchesOnlyCandidatesThatCanReachShortlist()
    {
        string coldDir = Directory.CreateTempSubdirectory().FullName;
        string fullDir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var candidates = Enumerable.Range(1, 30)
                .Select(index => new ProviderCandidate(
                    (uint)index,
                    $"Provider {index}",
                    null,
                    null,
                    "Content",
                    index <= 2 ? 100 : 0,
                    null,
                    [$"11.{index}.0.0/24"],
                    TotalIpCount: index <= 2 ? 1_000_000 : 1))
                .ToList();

            var coldCache = new RipeStatCache(coldDir);
            PrimeScoringCache(coldCache, candidates);
            var rpkiHandler = TestHttpMessageHandler.Always(
                HttpStatusCode.OK,
                "{\"status\":\"ok\",\"data\":{\"status\":\"valid\"}}");
            var coldResults = await CreateScorer(
                    coldDir, coldCache, new RipeStatClient(new HttpClient(rpkiHandler), coldCache))
                .ScoreAsync(candidates, null, returnTop: 2, pingTopN: 2,
                    strictAbuseFilter: false);

            var fullCache = new RipeStatCache(fullDir);
            PrimeScoringCache(fullCache, candidates);
            foreach (var candidate in candidates)
                fullCache.Set($"rpki_{candidate.Asn}", "{\"r\":1.0}", TimeSpan.FromDays(1));
            var fullResults = await CreateScorer(
                    fullDir, fullCache, new RipeStatClient(new HttpClient(), fullCache))
                .ScoreAsync(candidates, null, returnTop: 2, pingTopN: 2,
                    strictAbuseFilter: false);

            coldResults.Select(result => result.Asn)
                .Should().BeEquivalentTo(fullResults.Select(result => result.Asn));
            rpkiHandler.Requests.Should().HaveCountLessThan(candidates.Count);
        }
        finally
        {
            Directory.Delete(coldDir, true);
            Directory.Delete(fullDir, true);
        }
    }

    [Fact]
    public async Task ScoreAsync_ExpiredNetworkBudgetKeepsLocalCandidates()
    {
        string dataDir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var candidates = Enumerable.Range(1, 5)
                .Select(index => new ProviderCandidate(
                    (uint)index,
                    $"Provider {index}",
                    null,
                    null,
                    "Content",
                    index,
                    null,
                    [$"12.{index}.0.0/24"]))
                .ToList();
            var cache = new RipeStatCache(dataDir);
            var ripeHttp = new HttpClient(TestHttpMessageHandler.Custom(_ =>
                throw new InvalidOperationException("RIPE Stat should not be called")));

            var results = await CreateScorer(
                    dataDir, cache, new RipeStatClient(ripeHttp, cache))
                .ScoreAsync(
                    candidates,
                    maxPingMs: null,
                    returnTop: 3,
                    pingTopN: 5,
                    strictAbuseFilter: false,
                    networkBudget: TimeSpan.Zero);

            results.Should().HaveCount(3);
            results.Should().OnlyContain(result => result.LatencyMs == null);
        }
        finally
        {
            Directory.Delete(dataDir, true);
        }
    }

    private static ProviderScorer CreateScorer(
        string dataDir,
        RipeStatCache cache,
        RipeStatClient ripeStat)
    {
        var spamhausHttp = new HttpClient(TestHttpMessageHandler.Always(
            HttpStatusCode.OK, "AS65000 ; test\n"));
        var ipapiHttp = new HttpClient(TestHttpMessageHandler.Custom(_ =>
            throw new InvalidOperationException("ipapi should be served from cache")));
        return new ProviderScorer(
            new SpamhausDropClient(spamhausHttp, dataDir),
            new IpapiIsClient(ipapiHttp),
            new CleanReputation(),
            new PingService(),
            ripeCache: cache,
            ripeStat: ripeStat);
    }

    private static void PrimeScoringCache(
        RipeStatCache cache,
        IEnumerable<ProviderCandidate> candidates)
    {
        foreach (var candidate in candidates)
        {
            cache.Set($"abuse_{candidate.Asn}", ProviderScorer.SerializeAbuse(0), TimeSpan.FromDays(1));
            string anchor = ProviderScorer.GetAnchorIp(candidate.Prefixes[0])!;
            cache.Set($"ping_{anchor}", ProviderScorer.SerializePingOrNull(null), TimeSpan.FromDays(1));
        }
    }
}
