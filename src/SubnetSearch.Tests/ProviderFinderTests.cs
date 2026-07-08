using FluentAssertions;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Офлайн-покрытие таксономии vps / dedicated / cloud (TAX-01, D-05/D-06):
//   - --type алиасы: vps/dedicated/server/hosting/cloud дают одинаковые PeeringDB info_types
//     (различие применяется пост-фильтром, не на info_type) — D-03/D-04.
//   - Предикаты IsVpsFilter/IsDedicatedFilter/IsCloudFilter матчат только собственный алиас.
//   - ApplyTaxonomyFilter — чистая функция: эталоны i3D (AS49544, dedicated), AWS (AS16509, cloud),
//     Hetzner (AS24940) и PLAY2GO (AS215439, неразмечен → vps, D-06).
public class ProviderFinderTests
{
    private static ProviderCandidate C(uint asn, string name = "prov")
        => new(asn, name, null, null, null, null, null, []);

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

    [Theory]
    [InlineData("vps", true)]
    [InlineData("VPS", true)]
    [InlineData("dedicated", false)]
    [InlineData("server", false)]
    [InlineData("hosting", false)]
    [InlineData("cloud", false)]
    [InlineData(null, false)]
    public void IsVpsFilter_MatchesOnlyVpsAlias(string? type, bool expected)
    {
        ProviderFinder.IsVpsFilter(type).Should().Be(expected);
    }

    [Theory]
    [InlineData("dedicated", true)]
    [InlineData("DEDICATED", true)]
    [InlineData("vps", false)]
    [InlineData("server", false)]
    [InlineData(null, false)]
    public void IsDedicatedFilter_MatchesOnlyDedicatedAlias(string? type, bool expected)
    {
        ProviderFinder.IsDedicatedFilter(type).Should().Be(expected);
    }

    [Theory]
    [InlineData("cloud", true)]
    [InlineData("CLOUD", true)]
    [InlineData("vps", false)]
    [InlineData("dedicated", false)]
    [InlineData("server", false)]
    [InlineData("hosting", false)]
    [InlineData(null, false)]
    public void IsCloudFilter_MatchesOnlyCloudAlias(string? type, bool expected) // D-05
    {
        ProviderFinder.IsCloudFilter(type).Should().Be(expected);
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

    // Матрица ApplyTaxonomyFilter: ded={49544 (i3D)}, cloud={16509 (AWS)}.
    // Вход: i3D (dedicated), AWS (cloud), Hetzner (24940, unmarked), PLAY2GO (215439, unmarked, D-06).
    private static readonly IReadOnlyList<ProviderCandidate> _taxonomyInput =
        [C(49544, "i3D"), C(16509, "AWS"), C(24940, "Hetzner"), C(215439, "PLAY2GO")];
    private static readonly HashSet<uint> _dedicatedSet = [49544];
    private static readonly HashSet<uint> _cloudSet     = [16509];

    [Fact]
    public void ApplyTaxonomyFilter_Vps_DropsDedicatedAndCloudOnlyAsns() // i3D+AWS скрыты, PLAY2GO виден (D-06)
    {
        var result = ProviderFinder.ApplyTaxonomyFilter(_taxonomyInput, _dedicatedSet, _cloudSet, "vps");

        result.Select(c => c.Asn).Should().BeEquivalentTo(new uint[] { 24940, 215439 });
    }

    [Fact]
    public void ApplyTaxonomyFilter_Dedicated_KeepsOnlyDedicatedOnlyAsn() // i3D виден в --type dedicated
    {
        var result = ProviderFinder.ApplyTaxonomyFilter(_taxonomyInput, _dedicatedSet, _cloudSet, "dedicated");

        result.Select(c => c.Asn).Should().Equal(49544u);
    }

    [Fact]
    public void ApplyTaxonomyFilter_Cloud_KeepsOnlyCloudOnlyAsn() // AWS виден только в --type cloud (D-05)
    {
        var result = ProviderFinder.ApplyTaxonomyFilter(_taxonomyInput, _dedicatedSet, _cloudSet, "cloud");

        result.Select(c => c.Asn).Should().Equal(16509u);
    }

    [Theory]
    [InlineData("server")]
    [InlineData("hosting")]
    [InlineData(null)]
    public void ApplyTaxonomyFilter_Umbrella_ReturnsAllUnchanged(string? type) // зонтик = vps ∪ dedicated ∪ cloud
    {
        var result = ProviderFinder.ApplyTaxonomyFilter(_taxonomyInput, _dedicatedSet, _cloudSet, type);

        result.Select(c => c.Asn).Should().BeEquivalentTo(new uint[] { 49544, 16509, 24940, 215439 });
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
}
