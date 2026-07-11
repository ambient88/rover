using FluentAssertions;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Рейтинговый алгоритм с пресетами: ScoringWeights (Balanced/Performance/Security),
// редистрибуция весов при отсутствии данных, объединение источников репутации.
public class ScoringPresetsTests
{
    // ── Пресеты: разбор имени ──

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

    // ── Пресеты влияют на итоговый балл ──

    [Fact]
    public void Preset_Performance_RewardsLowLatencyOverCleanReputation()
    {
        // Провайдер: отличная задержка (5мс), грязная репутация (abuse 0.9).
        // Performance (latency-вес 0.45) ценит его выше, чем Security (reputation-вес 0.45).
        double perf = ProviderScorer.ComputeScore(
            5, null, 20, 100, 0.9, 0.9, null, null, 0.5, weights: ScoringWeights.Performance).Score;
        double sec = ProviderScorer.ComputeScore(
            5, null, 20, 100, 0.9, 0.9, null, null, 0.5, weights: ScoringWeights.Security).Score;

        perf.Should().BeGreaterThan(sec);
    }

    [Fact]
    public void Preset_Security_RewardsCleanReputationOverLowLatency()
    {
        // Провайдер: чистая репутация, но высокая задержка (180мс).
        // Security (reputation-вес) ценит его выше, чем Performance (latency-вес).
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

    // ── Редистрибуция весов: отсутствие данных не штрафует ──

    [Fact]
    public void ComputeScore_MissingLatency_RedistributesWeight_NoPenalty()
    {
        // Отличный по всем сигналам провайдер без ping-данных всё равно набирает высокий балл:
        // вес задержки перераспределяется на доступные компоненты, а не обнуляет их.
        double noLatency = ProviderScorer.ComputeScore(
            null, null, 100, 1000, 0.0, 0.0, null, null, 1.0, totalIpCount: 1_000_000).Score;

        noLatency.Should().BeGreaterThan(0.85);
    }

    [Fact]
    public void ComputeScore_MissingRpki_RedistributesWeight_NoPenalty()
    {
        // Без RPKI-данных балл не должен быть ниже, чем с нулевым RPKI (это был бы штраф).
        double missingRpki = ProviderScorer.ComputeScore(
            10, null, 100, 1000, 0.0, 0.0, null, null, rpkiScore: null, totalIpCount: 1_000_000).Score;
        double zeroRpki = ProviderScorer.ComputeScore(
            10, null, 100, 1000, 0.0, 0.0, null, null, rpkiScore: 0.0, totalIpCount: 1_000_000).Score;

        missingRpki.Should().BeGreaterThan(zeroRpki);
    }

    // ── Репутация объединяется из всех доступных источников ──

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
        // Экстремумы обоих концов остаются в [0,1] при любом пресете.
        // Допуск eps: при идеальных входах перераспределение весов даёт ~1.0 ± флоат-погрешность
        // (наблюдалось 1.0000000000000002) — это округление double, а не выход за диапазон.
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
