using FluentAssertions;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

public class ProviderScorerTests
{
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

    // ── Пинг-кэш (D-05, Phase 10): сериализация и round-trip через RipeStatCache ──

    [Fact]
    public void SerializePingOrNull_RoundTripsPopulatedStats() // положительный результат
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
    public void SerializePingOrNull_RoundTripsNull() // отрицательный результат (молчащий хост)
    {
        var json = ProviderScorer.SerializePingOrNull(null);
        ProviderScorer.DeserializePingOrNull(json).Should().BeNull();
    }

    [Fact]
    public void PingCache_HitPath_ReconstructsStatsFromRealCache() // путь попадания без спавна ping
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
    public void PingCache_NegativeHit_SignalsSkipWithoutRePing() // кэшированный молчащий хост
    {
        var dir = Path.Combine(Path.GetTempPath(), $"scorer-cache-{Guid.NewGuid():N}");
        try
        {
            var cache = new RipeStatCache(dir);
            cache.Set("ping_10.0.0.1", ProviderScorer.SerializePingOrNull(null), TimeSpan.FromMinutes(10));

            // TryGet == true при десериализации в null — сигнал «хост молчит, не пинговать повторно».
            cache.TryGet("ping_10.0.0.1", out var json).Should().BeTrue();
            ProviderScorer.DeserializePingOrNull(json!).Should().BeNull();
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void DeserializePingOrNull_ToleratesCorruptJson()
        => ProviderScorer.DeserializePingOrNull("{ not json ]").Should().BeNull();

    // ── WR-08: битый JSON дизамбигуирован от настоящего негативного хита ──

    [Fact]
    public void TryDeserializePing_CorruptJson_SignalsCacheMiss() // false → IP уйдёт в пробу
    {
        ProviderScorer.TryDeserializePing("{ not json ]", out var stats).Should().BeFalse();
        stats.Should().BeNull();
    }

    [Fact]
    public void TryDeserializePing_NegativeHit_SignalsKnownSilent() // true + null → хост молчит
    {
        var json = ProviderScorer.SerializePingOrNull(null);
        ProviderScorer.TryDeserializePing(json, out var stats).Should().BeTrue();
        stats.Should().BeNull();
    }

    [Fact]
    public void TryDeserializePing_PositiveHit_ReturnsStats() // true + stats → живой хост из кэша
    {
        var json = ProviderScorer.SerializePingOrNull(
            new SubnetSearch.Core.Models.Classification.PingStats(1.0, 2.0, 3.0, 0));
        ProviderScorer.TryDeserializePing(json, out var stats).Should().BeTrue();
        stats.Should().NotBeNull();
        stats!.AvgMs.Should().Be(2.0);
    }

    // ── Abuse-кэш (Phase 10, «ещё быстрее»): abuser_score ipapi.is кэшируется по ASN ──

    [Fact]
    public void SerializeAbuse_RoundTripsScore() // положительный результат
    {
        var json = ProviderScorer.SerializeAbuse(0.0042);
        ProviderScorer.DeserializeAbuseOrNull(json).Should().Be(0.0042);
    }

    [Fact]
    public void SerializeAbuse_RoundTripsNull() // отрицательный результат (нет данных / сбой API)
    {
        var json = ProviderScorer.SerializeAbuse(null);
        ProviderScorer.DeserializeAbuseOrNull(json).Should().BeNull();
    }

    [Fact]
    public void AbuseCache_HitPath_ReconstructsScoreFromRealCache() // попадание без HTTP-запроса
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
}
