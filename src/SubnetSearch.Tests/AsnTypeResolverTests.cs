using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

// These priorities reflect real conflicts between classification sources.
// Blizzard AS57976 has an incorrect hosting category in as.json, while bgp.tools marks it as CDN.
// CG-Net AS16247 has an ISP category in as.json and a stale vpsh tag in bgp.tools.
// OVH AS16276 has hosting in as.json plus vpsh and CDN tags, with vpsh taking priority.
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
        // as.json labels more than 12,000 ASNs as hosting, including F5 and Cisco Umbrella.
        // This category is too broad to produce a positive result without a vpsh tag.
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

    // Access tags take priority over vpsh tags.

    [Theory]
    [InlineData("dsl")]
    [InlineData("mobile")]
    [InlineData("satnet")]
    public void AccessTag_BeatsVpsh_EvenWithAsJsonHosting(string accessTag) // Wavenet AS5413
    {
        // A conflicting access tag from bgp.tools takes priority over a stale vpsh tag,
        // even when as.json labels the ASN as hosting.
        var map = Build(
            Tags(("vpsh", [5413u]), (accessTag, [5413u])),
            new() { [5413] = "hosting" });

        map[5413].Should().Be("isp");
    }

    [Fact]
    public void VpshOnly_WithAsJsonHosting_StaysHosting() // Covers Claranet AS8426.
    {
        // Without a conflicting access tag, vpsh still produces a hosting classification.
        var map = Build(
            Tags(("vpsh", [8426u])),
            new() { [8426] = "hosting" });

        map[8426].Should().Be("hosting");
    }

    [Theory]
    [InlineData("corp")]
    [InlineData("biznet")]
    public void BusinessTag_StaysBelowVpsh(string bizTag) // Business tags do not override vpsh.
    {
        var map = Build(
            Tags(("vpsh", [4242u]), (bizTag, [4242u])),
            new());

        map[4242].Should().Be("hosting");
    }
}
