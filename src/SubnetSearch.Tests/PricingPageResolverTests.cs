using FluentAssertions;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// PricingPageResolver: ASN → URL (точное совпадение), затем ключевое слово в имени организации.
public class PricingPageResolverTests
{
    [Fact]
    public void Resolve_KnownAsn_ReturnsUrl()
        => PricingPageResolver.Resolve(24940, orgName: null)
            .Should().Be("https://www.hetzner.com/cloud/");

    [Fact]
    public void Resolve_AsnWinsOverName()
        => PricingPageResolver.Resolve(24940, orgName: "OVH SAS")
            .Should().Be("https://www.hetzner.com/cloud/", "ASN проверяется раньше имени");

    [Fact]
    public void Resolve_UnknownAsn_FallsBackToKeyword()
        => PricingPageResolver.Resolve(999999, "OVH GmbH")
            .Should().Be("https://www.ovhcloud.com/en/vps/");

    [Fact]
    public void Resolve_KeywordCaseInsensitive()
        => PricingPageResolver.Resolve(999999, "digitalocean llc")
            .Should().Be("https://www.digitalocean.com/pricing/");

    [Fact]
    public void Resolve_UnknownAsnAndName_ReturnsNull()
        => PricingPageResolver.Resolve(999999, "Totally Unknown Provider").Should().BeNull();

    [Fact]
    public void Resolve_NullOrgName_UnknownAsn_ReturnsNull() // краевой случай
        => PricingPageResolver.Resolve(999999, null).Should().BeNull();

    [Fact]
    public void Resolve_WhitespaceOrgName_ReturnsNull() // краевой случай
        => PricingPageResolver.Resolve(999999, "   ").Should().BeNull();
}
