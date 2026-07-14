using FluentAssertions;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Covers scoring presets, missing-data weight redistribution, and reputation source aggregation.
public class ScoringPresetsTests
{
    // Preset name parsing.

    [Theory]
    [InlineData("performance")]
    [InlineData("PERFORMANCE")]
    [InlineData("Performance")]
    public void FromName_Performance_IsCaseInsensitive(string name)
        => ScoringWeights.FromName(name).Should().Be(ScoringWeights.Performance);

    [Theory]
    [InlineData("security")]
    [InlineData("Security")]
    public void FromName_Security(string name)
        => ScoringWeights.FromName(name).Should().Be(ScoringWeights.Security);

    [Theory]
    [InlineData("balanced")]
    [InlineData("unknown-preset")]
    [InlineData("")]
    [InlineData(null)]
    public void FromName_FallsBackToBalanced(string? name)
        => ScoringWeights.FromName(name).Should().Be(ScoringWeights.Balanced);

    [Fact]
    public void Presets_HaveDistinctWeightProfiles()
    {
        ScoringWeights.Performance.Latency.Should().BeGreaterThan(ScoringWeights.Balanced.Latency);
        ScoringWeights.Security.Reputation.Should().BeGreaterThan(ScoringWeights.Balanced.Reputation);
        ScoringWeights.Security.Rpki.Should().BeGreaterThan(ScoringWeights.Performance.Rpki);
    }

    // Presets affect the final score.

    [Fact]
    public void Preset_Performance_RewardsLowLatencyOverCleanReputation()
    {
        // The performance preset values a provider with 5 ms latency and poor reputation
        // more highly than the security preset does.
        double perf = ProviderScorer.ComputeScore(
            5, null, 20, 100, 0.9, 0.9, null, null, 0.5, weights: ScoringWeights.Performance).Score;
        double sec = ProviderScorer.ComputeScore(
            5, null, 20, 100, 0.9, 0.9, null, null, 0.5, weights: ScoringWeights.Security).Score;

        perf.Should().BeGreaterThan(sec);
    }

    [Fact]
    public void Preset_Security_RewardsCleanReputationOverLowLatency()
    {
        // The security preset values a clean provider with 180 ms latency
        // more highly than the performance preset does.
        double sec = ProviderScorer.ComputeScore(
            180, null, 20, 100, 0.0, 0.0, null, null, 1.0, weights: ScoringWeights.Security).Score;
        double perf = ProviderScorer.ComputeScore(
            180, null, 20, 100, 0.0, 0.0, null, null, 1.0, weights: ScoringWeights.Performance).Score;

        sec.Should().BeGreaterThan(perf);
    }

    [Fact]
    public void ComputeScore_DefaultsToBalanced_WhenWeightsNull()
    {
        double implicitBalanced = ProviderScorer.ComputeScore(
            50, null, 20, 100, 0.1, 0.1, null, null, 0.8, weights: null).Score;
        double explicitBalanced = ProviderScorer.ComputeScore(
            50, null, 20, 100, 0.1, 0.1, null, null, 0.8, weights: ScoringWeights.Balanced).Score;

        implicitBalanced.Should().Be(explicitBalanced);
    }

    // Missing data redistributes its weight without a penalty.

    [Fact]
    public void ComputeScore_MissingLatency_RedistributesWeight_NoPenalty()
    {
        // A provider with strong available signals still scores well without ping data
        // because the latency weight moves to the remaining components.
        double noLatency = ProviderScorer.ComputeScore(
            null, null, 100, 1000, 0.0, 0.0, null, null, 1.0, totalIpCount: 1_000_000).Score;

        noLatency.Should().BeGreaterThan(0.85);
    }

    [Fact]
    public void ComputeScore_MissingRpki_RedistributesWeight_NoPenalty()
    {
        // Missing RPKI data must score higher than an explicit zero RPKI value.
        double missingRpki = ProviderScorer.ComputeScore(
            10, null, 100, 1000, 0.0, 0.0, null, null, rpkiScore: null, totalIpCount: 1_000_000).Score;
        double zeroRpki = ProviderScorer.ComputeScore(
            10, null, 100, 1000, 0.0, 0.0, null, null, rpkiScore: 0.0, totalIpCount: 1_000_000).Score;

        missingRpki.Should().BeGreaterThan(zeroRpki);
    }

    [Fact]
    public void ComputeScore_MissingPeeringCount_RedistributesWeight_NoPenalty()
    {
        double missingPeering = ProviderScorer.ComputeScore(
            10, null, null, 1000, 0.0, 0.0, null, null, 1.0,
            totalIpCount: 1_000_000).Score;
        double zeroPeering = ProviderScorer.ComputeScore(
            10, null, 0, 1000, 0.0, 0.0, null, null, 1.0,
            totalIpCount: 1_000_000).Score;

        missingPeering.Should().BeGreaterThan(zeroPeering);
    }

    // Reputation combines all available sources.

    [Fact]
    public void ComputeScore_HigherAbuseIpDbScore_LowersScore()
    {
        double clean = ProviderScorer.ComputeScore(10, null, 20, 100, 0.0, 0.0, abuseIpDbScore: 0.0, null, 0.5).Score;
        double dirty = ProviderScorer.ComputeScore(10, null, 20, 100, 0.0, 0.0, abuseIpDbScore: 90.0, null, 0.5).Score;

        clean.Should().BeGreaterThan(dirty, "AbuseIPDB score 0-100 нормализуется и ухудшает репутацию");
    }

    [Fact]
    public void ComputeScore_HigherGreyNoiseRatio_LowersScore()
    {
        double clean = ProviderScorer.ComputeScore(10, null, 20, 100, 0.0, 0.0, null, greyNoiseRatio: 0.0, 0.5).Score;
        double dirty = ProviderScorer.ComputeScore(10, null, 20, 100, 0.0, 0.0, null, greyNoiseRatio: 0.9, 0.5).Score;

        clean.Should().BeGreaterThan(dirty, "доля malicious GreyNoise учитывается в репутации");
    }

    [Fact]
    public void ComputeScore_UpstreamCount_ImprovesPeeringComponent()
    {
        double noUpstream = ProviderScorer.ComputeScore(
            10, null, 10, 100, 0.0, 0.0, null, null, 0.5, upstreamCount: 0).Score;
        double withUpstream = ProviderScorer.ComputeScore(
            10, null, 10, 100, 0.0, 0.0, null, null, 0.5, upstreamCount: 8).Score;

        withUpstream.Should().BeGreaterThan(noUpstream, "транзит-провайдеры усиливают peering-компонент");
    }

    [Fact]
    public void ComputeScore_ResultAlwaysInUnitRange()
    {
        // Extreme inputs remain within the unit range for every preset.
        // The tolerance accounts for normal double rounding near 1.0.
        const double eps = 1e-9;
        foreach (var w in new[] { ScoringWeights.Balanced, ScoringWeights.Performance, ScoringWeights.Security })
        {
            ProviderScorer.ComputeScore(0, 0, 500, 100000, 0.0, 0.0, 0.0, 0.0, 1.0,
                totalIpCount: 10_000_000, weights: w).Score.Should().BeInRange(0.0, 1.0 + eps);
            ProviderScorer.ComputeScore(500, 100, 0, 1, 1.0, 1.0, 100.0, 1.0, 0.0,
                weights: w).Score.Should().BeInRange(0.0 - eps, 1.0 + eps);
        }
    }
}
