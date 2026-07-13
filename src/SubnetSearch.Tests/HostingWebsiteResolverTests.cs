using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

// HostingWebsiteResolver.GetWebsite: приоритет источников сайта —
// whois → byAsn → byOrg (точное) → ManualOverrides (точное) → ManualOverrides (подстрока) → byOrg (подстрока).
public class HostingWebsiteResolverTests
{
    private static HostingWebsiteResolver Resolver(
        Dictionary<uint, string>? byAsn = null,
        Dictionary<string, string>? byOrg = null)
        => new(byAsn ?? new(), byOrg ?? new(StringComparer.OrdinalIgnoreCase), peeringDbResolver: null);

    [Fact]
    public void GetWebsite_WhoisWebsite_HasHighestPriority()
    {
        var r = Resolver(byAsn: new() { [1] = "https://from-asn" });

        r.GetWebsite(1, "AnyOrg", whoisWebsite: "https://from-whois")
            .Should().Be("https://from-whois");
    }

    [Fact]
    public void GetWebsite_ByAsn_ExactMatch()
        => Resolver(byAsn: new() { [24940] = "https://hetzner.example" })
            .GetWebsite(24940, null).Should().Be("https://hetzner.example");

    [Fact]
    public void GetWebsite_ByOrg_ExactMatch()
        => Resolver(byOrg: new(StringComparer.OrdinalIgnoreCase) { ["MyCorp"] = "https://mycorp.example" })
            .GetWebsite(null, "mycorp").Should().Be("https://mycorp.example", "byOrg регистронезависим");

    [Fact]
    public void GetWebsite_ManualOverride_ExactMatch()
        => Resolver().GetWebsite(null, "HETZNER").Should().Be("https://www.hetzner.com");

    [Fact]
    public void GetWebsite_ManualOverride_SubstringMatch()
        => Resolver().GetWebsite(null, "DigitalOcean, LLC")
            .Should().Be("https://www.digitalocean.com", "подстрока в имени организации");

    [Fact]
    public void GetWebsite_ByOrg_SubstringMatch()
        => Resolver(byOrg: new(StringComparer.OrdinalIgnoreCase) { ["ACME"] = "https://acme.example" })
            .GetWebsite(null, "The ACME Company").Should().Be("https://acme.example");

    [Fact]
    public void GetWebsite_PositiveSubstringResultIsMemoized()
    {
        var organizations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ACME"] = "https://acme.example"
        };
        var resolver = Resolver(byOrg: organizations);

        resolver.GetWebsite(null, "The ACME Company").Should().Be("https://acme.example");
        organizations.Clear();

        resolver.GetWebsite(null, "The ACME Company").Should().Be("https://acme.example");
    }

    [Fact]
    public void GetWebsite_NegativeSubstringResultIsMemoized()
    {
        var organizations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var resolver = Resolver(byOrg: organizations);

        resolver.GetWebsite(null, "The ACME Company").Should().BeNull();
        organizations["ACME"] = "https://acme.example";

        resolver.GetWebsite(null, "The ACME Company").Should().BeNull();
    }

    [Fact]
    public void GetWebsite_NoMatch_ReturnsNull()
        => Resolver().GetWebsite(999999, "Totally Unknown Provider").Should().BeNull();

    [Fact]
    public void GetWebsite_NullAsnAndOrg_ReturnsNull() // краевой случай
        => Resolver().GetWebsite(null, null).Should().BeNull();

    [Fact]
    public async Task GetNetworkInfo_NoPeeringDbResolver_ReturnsNull()
        => (await Resolver().GetNetworkInfoFromPeeringDbAsync(24940)).Should().BeNull();

    [Fact]
    public async Task GetIxLocations_NoPeeringDbResolver_ReturnsNull()
        => (await Resolver().GetIxLocationsAsync(24940)).Should().BeNull();
}
