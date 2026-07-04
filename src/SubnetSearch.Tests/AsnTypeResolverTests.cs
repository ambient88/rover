using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

// Приоритеты выверены на реальных конфликтах источников (см. AsnTypeResolver):
//   Blizzard AS57976: as.json=hosting (ошибка), bgp.tools=cdn → должен стать "cdn" (reject).
//   CG-Net  AS16247: as.json=isp, bgp.tools=vpsh (устаревший)  → "isp" (reject).
//   OVH     AS16276: as.json=hosting, bgp.tools=vpsh+cdn        → "hosting" (vpsh бьёт cdn).
public class AsnTypeResolverTests
{
    private static IReadOnlyDictionary<uint, string> Build(
        Dictionary<string, HashSet<uint>> tags,
        Dictionary<uint, string> categories)
        => AsnTypeResolver.Build(tags, categories);

    private static Dictionary<string, HashSet<uint>> Tags(params (string Tag, uint[] Asns)[] entries)
        => entries.ToDictionary(e => e.Tag, e => new HashSet<uint>(e.Asns));

    [Fact]
    public void CdnTagWithoutVpsh_BeatsWrongAsJsonHosting() // Blizzard case
    {
        var map = Build(
            Tags(("cdn", [57976u])),
            new() { [57976] = "hosting" });

        map[57976].Should().Be("cdn");
    }

    [Fact]
    public void AsJsonIsp_BeatsStaleVpshTag() // CG-Net case
    {
        var map = Build(
            Tags(("vpsh", [16247u])),
            new() { [16247] = "isp" });

        map[16247].Should().Be("isp");
    }

    [Fact]
    public void VpshTag_BeatsCdnTag() // OVH/AWS/Google carry both tags
    {
        var map = Build(
            Tags(("vpsh", [16276u]), ("cdn", [16276u])),
            new() { [16276] = "hosting" });

        map[16276].Should().Be("hosting");
    }

    [Fact]
    public void VpshTag_WithoutAsJsonEntry_IsHosting()
    {
        var map = Build(Tags(("vpsh", [44684u])), new());

        map[44684].Should().Be("hosting");
    }

    [Theory]
    [InlineData("dsl", "isp")]
    [InlineData("mobile", "isp")]
    [InlineData("satnet", "isp")]
    [InlineData("gov", "government")]
    [InlineData("uni", "education")]
    [InlineData("perso", "personal")]
    [InlineData("corp", "business")]
    [InlineData("biznet", "business")]
    [InlineData("event", "business")]
    public void NegativeTags_MapToNonHostingTypes(string tag, string expected)
    {
        var map = Build(Tags((tag, [999u])), new());

        map[999].Should().Be(expected);
    }

    [Fact]
    public void AsJsonHostingAlone_IsNotAPositiveVerdict() // F5/Cisco Umbrella case
    {
        // as.json помечает "hosting" 12k+ ASN, включая F5 (AS35280) и Cisco Umbrella
        // (AS36692) — категория слишком щедрая, поэтому без vpsh-тега она не даёт
        // позитивный вердикт: ASN остаётся неизвестным (отсутствует в карте).
        var map = Build(Tags(), new() { [35280] = "hosting" });

        map.ContainsKey(35280).Should().BeFalse();
    }

    [Fact]
    public void AsJsonBusiness_StillMapsToBusiness()
    {
        var map = Build(Tags(), new() { [714] = "business" });

        map[714].Should().Be("business");
    }

    [Fact]
    public void AsJsonGovernment_BeatsVpsh()
    {
        var map = Build(
            Tags(("vpsh", [100u])),
            new() { [100] = "government_admin" });

        map[100].Should().Be("government");
    }

    [Fact]
    public void UnknownAsn_AbsentFromMap()
    {
        var map = Build(Tags(("vpsh", [1u])), new() { [2] = "hosting" });

        map.ContainsKey(3).Should().BeFalse();
    }

    [Fact]
    public void NullCategory_WithoutTags_AbsentFromMap()
    {
        var map = Build(Tags(), new());

        map.Should().BeEmpty();
    }
}
