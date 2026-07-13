using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

public class HostingWebsiteResolverGetWebsiteTests
{
    private static HostingWebsiteResolver Resolver(
        Dictionary<uint, string>? byAsn = null,
        Dictionary<string, string>? byOrg = null)
        => new(byAsn ?? new(), byOrg ?? new(StringComparer.OrdinalIgnoreCase));

    [Fact]
    public void GetWebsite_WhoisWebsite_TakesPriority()
        => Resolver().GetWebsite(64500, "Anything", "https://from-whois.example")
            .Should().Be("https://from-whois.example");

    [Fact]
    public void GetWebsite_ByAsnMap_Hit()
        => Resolver(byAsn: new() { [64500] = "https://by-asn.example" })
            .GetWebsite(64500, "Org").Should().Be("https://by-asn.example");

    [Fact]
    public void GetWebsite_ByOrgMap_Hit()
        => Resolver(byOrg: new(StringComparer.OrdinalIgnoreCase) { ["Acme"] = "https://by-org.example" })
            .GetWebsite(null, "Acme").Should().Be("https://by-org.example");

    [Fact]
    public void GetWebsite_ManualOverride_ResolvesKnownProvider()
        => Resolver().GetWebsite(null, "HETZNER").Should().Be("https://www.hetzner.com");

    [Fact]
    public void GetWebsite_NothingMatches_ReturnsNull()
        => Resolver().GetWebsite(999, "Totally Unknown Org").Should().BeNull();
}
