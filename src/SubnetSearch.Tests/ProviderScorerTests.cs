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
}
