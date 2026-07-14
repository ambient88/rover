using System.Net;
using FluentAssertions;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Network;

namespace SubnetSearch.Tests;

public class ProviderScannerTests
{
    private sealed class StubWebsiteResolver : IWebsiteResolver
    {
        public string? GetWebsite(uint? asn, string? organization, string? whoisWebsite = null) => null;
        public Task<PeeringDbNetworkInfo?> GetNetworkInfoFromPeeringDbAsync(uint asn, CancellationToken ct = default)
            => Task.FromResult<PeeringDbNetworkInfo?>(null);
        public Task<IReadOnlyList<string>?> GetIxLocationsAsync(uint asn, CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<string>?>(null);
    }

    private static readonly IReadOnlyDictionary<string, (HttpStatusCode, string)> Endpoints =
        new Dictionary<string, (HttpStatusCode, string)>
        {
            ["as-overview"] =
                (HttpStatusCode.OK, """{"status":"ok","data":{"holder":"SENKO-AS Senko Digital LLC","announced":true}}"""),
            ["announced-prefixes"] =
                (HttpStatusCode.OK, """{"status":"ok","data":{"prefixes":[{"prefix":"5.6.7.0/24"},{"prefix":"1.2.3.0/25"}]}}"""),
            ["asn-neighbours"] =
                (HttpStatusCode.OK, """{"status":"ok","data":{"neighbours":[{"asn":100,"type":"left","power":9}]}}"""),
            ["searchcomplete"] =
                (HttpStatusCode.OK, """{"status":"ok","data":{"categories":[{"category":"ASNs","suggestions":[{"value":"AS64500","description":"SENKO-AS Senko"}]}]}}"""),
        };

    private static ProviderScanner Build()
    {
        var handler = TestHttpMessageHandler.ByUrl(Endpoints);
        var ripe = new RipeStatClient(new HttpClient(handler));
        return new ProviderScanner(ripe, new StubWebsiteResolver());
    }

    [Fact]
    public async Task Scan_DirectAsn_ReturnsOverviewPrefixesAndTotals()
    {
        var result = await Build().ScanAsync("AS64500");

        result.Should().NotBeNull();
        result!.Asn.Should().Be(64500u);
        result.AsnHandle.Should().Be("SENKO-AS");
        result.Organization.Should().Be("Senko Digital LLC");
        result.Prefixes.Should().HaveCount(2);
        // A /24 contains 256 addresses and a /25 contains 128, for a total of 384.
        result.TotalIpCount.Should().Be(384);
    }

    [Fact]
    public async Task Scan_NameQuery_ResolvesViaSearch()
    {
        var result = await Build().ScanAsync("senko");

        result.Should().NotBeNull();
        result!.Asn.Should().Be(64500u, "search resolved the name to AS64500");
    }

    [Fact]
    public async Task Scan_UnresolvableQuery_ReturnsNull()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK,
            """{"status":"ok","data":{"categories":[]}}""");
        var scanner = new ProviderScanner(
            new RipeStatClient(new HttpClient(handler)), new StubWebsiteResolver());

        (await scanner.ScanAsync("no-such-provider")).Should().BeNull();
    }

    [Theory]
    [InlineData("1.2.3.0/24", 256L)]
    [InlineData("10.0.0.0/8", 16777216L)]
    [InlineData("bad", 0L)]
    public void CalcIpCount_Boundaries(string prefix, long expected)
        => ProviderScanner.CalcIpCount(prefix).Should().Be(expected);
}
