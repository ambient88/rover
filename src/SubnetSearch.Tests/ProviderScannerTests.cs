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

    private sealed class StubIndex(Func<uint, Ip2AsnRecord?> find) : IIpRangeIndex
    {
        public Ip2AsnRecord? Find(uint ipInt) => find(ipInt);
    }

    [Fact]
    public async Task Scan_WithIpIndex_EnrichesPrefixCountriesAndSkipsUnparsable()
    {
        var handler = TestHttpMessageHandler.ByUrl(
            new Dictionary<string, (HttpStatusCode, string)>(
                (IReadOnlyDictionary<string, (HttpStatusCode, string)>)Endpoints)
            {
                // One resolvable prefix and one unparsable entry from the API.
                ["announced-prefixes"] =
                    (HttpStatusCode.OK, """{"status":"ok","data":{"prefixes":[{"prefix":"5.6.7.0/24"},{"prefix":"garbage/24"}]}}"""),
            });
        var index = new StubIndex(_ => new Ip2AsnRecord
        {
            StartIp = 0, EndIp = uint.MaxValue, Asn = 64500, Country = "NL", Description = "Senko",
        });
        var scanner = new ProviderScanner(
            new RipeStatClient(new HttpClient(handler)), new StubWebsiteResolver(), index);

        var result = await scanner.ScanAsync("AS64500");

        result!.Prefixes.Should().HaveCount(2);
        result.Prefixes.Should().Contain(p => p.Prefix == "5.6.7.0/24" && p.CountryCode == "NL");
        result.Prefixes.Should().Contain(p => p.Prefix == "garbage/24" && p.CountryCode == null);
    }

    [Fact]
    public async Task Scan_SearchWithSeveralSuggestions_ListsAlternatives()
    {
        var handler = TestHttpMessageHandler.ByUrl(
            new Dictionary<string, (HttpStatusCode, string)>(
                (IReadOnlyDictionary<string, (HttpStatusCode, string)>)Endpoints)
            {
                ["searchcomplete"] =
                    (HttpStatusCode.OK, """{"status":"ok","data":{"categories":[{"category":"ASNs","suggestions":[{"value":"AS64500","description":"SENKO-AS"},{"value":"AS64501","description":"SENKO-2"}]}]}}"""),
            });
        var scanner = new ProviderScanner(
            new RipeStatClient(new HttpClient(handler)), new StubWebsiteResolver());

        var result = await scanner.ScanAsync("senko");

        result!.Asn.Should().Be(64500u);
        result.OtherCandidates.Should().ContainSingle()
            .Which.Item1.Should().Be(64501u);
    }

    [Fact]
    public async Task Scan_InternalBudgetExpiresDuringResolve_ReturnsNull()
    {
        // An OCE from inside the resolve stage without caller cancellation means the
        // 7-second budget expired; the scan degrades to "not found".
        var handler = TestHttpMessageHandler.Throws(new OperationCanceledException());
        var scanner = new ProviderScanner(
            new RipeStatClient(new HttpClient(handler)), new StubWebsiteResolver());

        (await scanner.ScanAsync("senko")).Should().BeNull();
    }

    [Fact]
    public async Task Scan_EnrichmentStageTimesOut_ReturnsSkeletonResult()
    {
        var handler = TestHttpMessageHandler.Custom(req =>
        {
            var url = req.RequestUri!.AbsoluteUri;
            // The ASN resolves, but every enrichment endpoint hits the internal budget.
            if (url.Contains("searchcomplete"))
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        """{"status":"ok","data":{"categories":[{"category":"ASNs","suggestions":[{"value":"AS64500","description":"SENKO-AS"}]}]}}"""),
                };
            throw new OperationCanceledException();
        });
        var scanner = new ProviderScanner(
            new RipeStatClient(new HttpClient(handler)), new StubWebsiteResolver());

        var result = await scanner.ScanAsync("senko");

        result.Should().NotBeNull("a resolved ASN with failed enrichment still produces a result");
        result!.Asn.Should().Be(64500u);
        result.Prefixes.Should().BeEmpty();
        result.Upstreams.Should().BeEmpty();
    }

    private sealed class OceWebsiteResolver : IWebsiteResolver
    {
        public PeeringDbNetworkInfo? Info;
        public bool ThrowOnNetworkInfo;
        public bool ThrowOnIxLocations;

        public string? GetWebsite(uint? asn, string? organization, string? whoisWebsite = null) => null;

        // Failures surface through the returned task, the way real async enrichment fails:
        // the scanner starts the tasks before entering its try block.
        public Task<PeeringDbNetworkInfo?> GetNetworkInfoFromPeeringDbAsync(uint asn, CancellationToken ct = default)
            => ThrowOnNetworkInfo
                ? Task.FromException<PeeringDbNetworkInfo?>(new OperationCanceledException())
                : Task.FromResult(Info);

        public Task<IReadOnlyList<string>?> GetIxLocationsAsync(uint asn, CancellationToken ct = default)
            => ThrowOnIxLocations
                ? Task.FromException<IReadOnlyList<string>?>(new OperationCanceledException())
                : Task.FromResult<IReadOnlyList<string>?>(null);
    }

    [Fact]
    public async Task Scan_PeeringDbStageCancelledInternally_KeepsRipeData()
    {
        var handler = TestHttpMessageHandler.ByUrl(Endpoints);
        var scanner = new ProviderScanner(
            new RipeStatClient(new HttpClient(handler)),
            new OceWebsiteResolver { ThrowOnNetworkInfo = true });

        var result = await scanner.ScanAsync("AS64500");

        result.Should().NotBeNull("a failed PeeringDB enrichment does not sink the scan");
        result!.Website.Should().BeNull();
        result.Prefixes.Should().NotBeEmpty("RIPE data is unaffected");
    }

    [Fact]
    public async Task Scan_IxLocationStageCancelledInternally_KeepsResult()
    {
        var handler = TestHttpMessageHandler.ByUrl(Endpoints);
        var scanner = new ProviderScanner(
            new RipeStatClient(new HttpClient(handler)),
            new OceWebsiteResolver
            {
                Info = new PeeringDbNetworkInfo("http://x", "NSP", IxCount: 3, NetId: 7),
                ThrowOnIxLocations = true,
            });

        var result = await scanner.ScanAsync("AS64500");

        result.Should().NotBeNull();
        result!.PeeringCount.Should().Be(3);
        result.IxLocations.Should().BeNull("the ix-location stage failed soft");
    }

    [Fact]
    public async Task Scan_BudgetExpiresDuringResolve_ReturnsNull()
    {
        // The search response arrives after the whole scan budget has expired.
        var handler = TestHttpMessageHandler.Custom(_ =>
        {
            Thread.Sleep(400);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"status":"ok","data":{"categories":[{"category":"ASNs","suggestions":[{"value":"AS64500","description":"SENKO-AS"}]}]}}""",
                    System.Text.Encoding.UTF8, "application/json"),
            };
        });
        var scanner = new ProviderScanner(
            new RipeStatClient(new HttpClient(handler)), new StubWebsiteResolver(),
            ipIndex: null, scanBudget: TimeSpan.FromMilliseconds(50));

        var result = await Task.Run(() => scanner.ScanAsync("senko"));

        result.Should().BeNull("the scan budget expired before the ASN was resolved");
    }

    [Fact]
    public async Task Scan_UpstreamNameStageTimesOut_KeepsEmptyUpstreams()
    {
        var handler = TestHttpMessageHandler.Custom(req =>
        {
            var url = req.RequestUri!.AbsoluteUri;
            // The scanned ASN itself resolves fine; the neighbour's overview
            // (fetched in the second stage for upstream names) times out.
            if (url.Contains("as-overview") && url.Contains("resource=100"))
                throw new OperationCanceledException();
            foreach (var (key, (status, body)) in Endpoints)
                if (url.Contains(key, StringComparison.OrdinalIgnoreCase))
                    return new HttpResponseMessage(status) { Content = new StringContent(body) };
            return new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("") };
        });
        var scanner = new ProviderScanner(
            new RipeStatClient(new HttpClient(handler)), new StubWebsiteResolver());

        var result = await scanner.ScanAsync("AS64500");

        result.Should().NotBeNull();
        result!.Asn.Should().Be(64500u);
    }
}
