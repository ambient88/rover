using System.Net;
using FluentAssertions;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Data;
using SubnetSearch.Network;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Deterministic (no cache / no parallel-race) tests that lock coverage safely above the target.
public class CoverageMarginTests
{
    // ── WhoisResolver: remaining RIR org-field branches ──
    [Fact]
    public void Whois_Afrinic_UsesDescr()
    {
        var r = WhoisResolver.ParseWhoisResponse("whois.afrinic.net", "descr: Africa Net Ltd\ncountry: ZA");
        r!.Organization.Should().Be("Africa Net Ltd");
        r.Rir.Should().Be("AFRINIC");
    }

    [Fact]
    public void Whois_Ripe_FallsThroughToNetname()
    {
        var r = WhoisResolver.ParseWhoisResponse("whois.ripe.net", "netname: EXAMPLE-NET\ncountry: DE");
        r!.Organization.Should().Be("EXAMPLE-NET");
    }

    // ── IpListAnalyzer.IsPublicAddress: IPv6 branches ──
    [Theory]
    [InlineData("2606:4700:4700::1111", true)]   // public IPv6
    [InlineData("fd00::1", false)]                // ULA (fc00::/7)
    [InlineData("fe80::1", false)]                // link-local
    [InlineData("::1", false)]                    // loopback
    public void IsPublicAddress_Ipv6(string ip, bool expected)
        => IpListAnalyzer.IsPublicAddress(IPAddress.Parse(ip)).Should().Be(expected);

    // ── ProviderScanner: RIPE-failure degradation (numeric ASN, all upstreams 503) ──
    private sealed class NullWebsiteResolver : IWebsiteResolver
    {
        public string? GetWebsite(uint? asn, string? organization, string? whoisWebsite = null) => null;
        public Task<PeeringDbNetworkInfo?> GetNetworkInfoFromPeeringDbAsync(uint asn, CancellationToken ct = default)
            => Task.FromResult<PeeringDbNetworkInfo?>(null);
        public Task<IReadOnlyList<string>?> GetIxLocationsAsync(uint asn, CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<string>?>(null);
    }

    [Fact]
    public async Task ProviderScanner_RipeUnavailable_ReturnsResultWithoutPrefixes()
    {
        var ripe = new RipeStatClient(new HttpClient(
            TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}")));
        var scanner = new ProviderScanner(ripe, new NullWebsiteResolver());

        var result = await scanner.ScanAsync("AS64500");

        result.Should().NotBeNull();
        result!.Asn.Should().Be(64500u);
        result.Prefixes.Should().BeEmpty();
        result.TotalIpCount.Should().Be(0);
    }

    // ── ProviderScanner.CalcIpCount /0 boundary ──
    [Fact]
    public void ProviderScanner_CalcIpCount_SlashZero()
        => ProviderScanner.CalcIpCount("0.0.0.0/0").Should().Be(4294967296L);

    // ── RipeStatClient: additional deterministic HTTP paths ──
    private static RipeStatClient Ripe(string body)
        => new(new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.OK, body)));

    [Fact]
    public async Task Ripe_GetPrefixes_Ipv6Only_ReturnsEmpty()
    {
        var p = await Ripe("""{"status":"ok","data":{"prefixes":[{"prefix":"2001:db8::/32"}]}}""")
            .GetPrefixesAsync(1);
        p.Should().BeEmpty("GetPrefixesAsync returns IPv4 only");
    }

    [Fact]
    public async Task Ripe_GetNeighbourCounts_NoData_ReturnsZero()
    {
        var (up, down) = await Ripe("""{"status":"ok","data":{"neighbours":[]}}""").GetNeighbourCountsAsync(1);
        up.Should().Be(0);
        down.Should().Be(0);
    }

    [Fact]
    public async Task Ripe_GetCountryAsns_NoMatchingResource_ReturnsEmpty()
    {
        var a = await Ripe("""{"status":"ok","data":{"countries":[{"resource":"NL","routed":[1]}]}}""")
            .GetCountryAsnsAsync("DE");
        a.Should().BeEmpty();
    }

    [Fact]
    public async Task Ripe_Search_NoAsnCategory_ReturnsEmpty()
    {
        var s = await Ripe("""{"status":"ok","data":{"categories":[{"category":"Other","suggestions":[]}]}}""")
            .SearchAsync("x");
        s.Should().BeEmpty();
    }

    [Fact]
    public async Task Ripe_MarkAndIsKnownEmpty_WithoutCache_False()
    {
        var client = new RipeStatClient(new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.OK, "{}")));
        client.MarkEmpty(1);
        client.IsKnownEmpty(1).Should().BeFalse("no cache configured");
    }

    // ── IpListAnalyzer pure helpers ──
    [Fact]
    public void RewriteGitHubUrl_NonBlobUrl_Unchanged()
        => IpListAnalyzer.RewriteGitHubUrl("https://example.com/list.txt")
            .Should().Be("https://example.com/list.txt");

    [Fact]
    public void RewriteGitHubUrl_BlobUrl_RewrittenToRaw()
        => IpListAnalyzer.RewriteGitHubUrl("https://github.com/u/r/blob/main/f.txt")
            .Should().Be("https://raw.githubusercontent.com/u/r/main/f.txt");

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("10.0.0.1", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("224.0.0.1", false)]
    public void IsPublicAddress_Ipv4(string ip, bool expected)
        => IpListAnalyzer.IsPublicAddress(IPAddress.Parse(ip)).Should().Be(expected);
}
