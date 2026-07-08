using FluentAssertions;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Офлайн-покрытие server-таксономии: --type алиасы vps/dedicated/server/hosting/cloud дают
// одинаковые PeeringDB info_types (различие членства применяется allowlist'ом, не на info_type).
// Членство server-фильтра проверяется через ServerProviders.IsAllowed (см. ServerProvidersTests) и
// ProviderFinder.ApplyServerAllowlist (тест ниже). Старая subtractive-модель ApplyTaxonomyFilter
// удалена вместе с предикатами Is*Filter.
public class ProviderFinderTests
{
    [Theory]
    [InlineData("vps")]
    [InlineData("VPS")]
    [InlineData("dedicated")]
    [InlineData("server")]
    [InlineData("hosting")]
    [InlineData("cloud")]
    public void ResolveInfoTypes_ServerFamily_ReturnsContentNspEnterprise(string type)
    {
        ProviderFinder.ResolveInfoTypes(type).Should().BeEquivalentTo(new[] { "Content", "NSP", "Enterprise" });
    }

    [Fact]
    public void ResolveInfoTypes_Nonsense_ReturnsNull() // валидация не ослаблена (T-2.1-02)
    {
        ProviderFinder.ResolveInfoTypes("nonsense").Should().BeNull();
    }

    [Fact]
    public void ResolveInfoTypes_Null_ReturnsNull()
    {
        ProviderFinder.ResolveInfoTypes(null).Should().BeNull();
    }

    // Регресс: dedicated остаётся «server-подобным» для CDN/AI-исключений (D-03).
    [Theory]
    [InlineData("vps")]
    [InlineData("dedicated")]
    public void ShouldExcludeCdnAndAi_StillTrue_ForVpsAndDedicated(string type)
    {
        ProviderFinder.ShouldExcludeCdn(type).Should().BeTrue();
        ProviderFinder.ShouldExcludeAi(type).Should().BeTrue();
    }

    // ShouldIncludeUnverifiedHostingCandidate: candidates whose local ASN type is unknown
    // (not "hosting"/"cloud", not an explicit reject). Regression coverage for wholesale NSP
    // carriers that used to slip through the local IP-range whitelist unconditionally:
    // Hurricane Electric (AS6939), Colt (AS8220), Equinix (AS15830), M247 (AS9009),
    // DataBank (AS13767) — all PeeringDB info_type=NSP, no positive vpsh tag.

    [Theory]
    [InlineData(true)]  // in whitelist — used to be enough on its own
    [InlineData(false)]
    public void NspCandidate_AlwaysRejected_RegardlessOfWhitelist(bool inWhitelist)
    {
        ProviderFinder.ShouldIncludeUnverifiedHostingCandidate(
            infoType: "NSP", caidaClassification: null, inWhitelist: inWhitelist,
            totalIpCount: 10_000_000, strictContentFilter: false)
            .Should().BeFalse();
    }

    [Theory]
    [InlineData("Enterprise")]
    [InlineData("Transit/Access")]
    public void CaidaNonHostingClass_Rejected_RegardlessOfWhitelist(string caidaClass)
    {
        ProviderFinder.ShouldIncludeUnverifiedHostingCandidate(
            infoType: "Content", caidaClassification: caidaClass, inWhitelist: true,
            totalIpCount: 10_000_000, strictContentFilter: false)
            .Should().BeFalse();
    }

    [Fact]
    public void ContentCandidate_InWhitelist_Passes_EvenWithSmallIpPool()
    {
        ProviderFinder.ShouldIncludeUnverifiedHostingCandidate(
            infoType: "Content", caidaClassification: null, inWhitelist: true,
            totalIpCount: 10, strictContentFilter: false)
            .Should().BeTrue();
    }

    [Fact]
    public void ContentCandidate_NotInWhitelist_PassesOnSize_WhenLenient()
    {
        ProviderFinder.ShouldIncludeUnverifiedHostingCandidate(
            infoType: "Content", caidaClassification: null, inWhitelist: false,
            totalIpCount: 1024, strictContentFilter: false)
            .Should().BeTrue();
    }

    [Fact]
    public void ContentCandidate_NotInWhitelist_RejectedBelowSizeThreshold()
    {
        ProviderFinder.ShouldIncludeUnverifiedHostingCandidate(
            infoType: "Content", caidaClassification: null, inWhitelist: false,
            totalIpCount: 1023, strictContentFilter: false)
            .Should().BeFalse();
    }

    [Fact]
    public void ContentCandidate_NotInWhitelist_RejectedInStrictMode_EvenWithLargeIpPool()
    {
        ProviderFinder.ShouldIncludeUnverifiedHostingCandidate(
            infoType: "Content", caidaClassification: null, inWhitelist: false,
            totalIpCount: 10_000_000, strictContentFilter: true)
            .Should().BeFalse();
    }

    // ── PeeringDB per-ASN кэш (Phase 10, «ещё быстрее»): pdb_{asn} в ripe_cache ──

    [Fact]
    public void SerializePdbNet_RoundTripsFoundRecord() // запись существует в PeeringDB
    {
        var c = new ProviderCandidate(24940, "Hetzner", "DE", "https://hetzner.com", "Content", 87, null, []);
        var json = ProviderFinder.SerializePdbNet(c, found: true);
        var back = ProviderFinder.DeserializePdbNetOrNull(json);
        back.Should().NotBeNull();
        back!.Found.Should().BeTrue();
        back.Name.Should().Be("Hetzner");
        back.Country.Should().Be("DE");
        back.InfoType.Should().Be("Content");
        back.PeeringCount.Should().Be(87);
    }

    [Fact]
    public void SerializePdbNet_RoundTripsNotFound() // негативный кэш: записи нет в PeeringDB
    {
        var json = ProviderFinder.SerializePdbNet(null, found: false);
        var back = ProviderFinder.DeserializePdbNetOrNull(json);
        back.Should().NotBeNull();
        back!.Found.Should().BeFalse();
        back.Name.Should().BeNull();
    }

    [Fact]
    public void DeserializePdbNetOrNull_ToleratesCorruptJson()
        => ProviderFinder.DeserializePdbNetOrNull("{ not json ]").Should().BeNull();

    [Fact]
    public async Task ApplyServerAllowlist_KeepsOnlyCore_DropsEverythingElse() // pure allowlist
    {
        // core: только Hetzner(vps). Ни карьер, ни vpsh-хвост НЕ проходят — гейт убран.
        var basePath = Path.Combine(Path.GetTempPath(), $"sp-{Guid.NewGuid():N}.json");
        File.WriteAllText(basePath, """{"providers":[{"asn":24940,"name":"Hetzner","types":["vps"]}]}""");
        var sp = await ServerProviders.LoadAsync(basePath, basePath + ".x");
        File.Delete(basePath);

        var candidates = new[]
        {
            new ProviderCandidate(24940, "Hetzner", "DE", null, "Content", 1, null, []),
            new ProviderCandidate(31027, "GlobalConnect", "DK", null, "NSP", 1, null, []),
            new ProviderCandidate(215439, "PLAY2GO", "PL", null, null, 1, null, []),
        };

        var kept = ProviderFinder.ApplyServerAllowlist(candidates, "vps", sp)
                                 .Select(c => c.Asn).ToHashSet();

        kept.Should().Contain(24940, "в ядре");
        kept.Should().NotContain(31027, "карьер не в ядре");
        kept.Should().NotContain(215439, "vpsh-хвост больше не проходит автоматически");
    }
}
