using System.Net;
using FluentAssertions;
using SubnetSearch.Network;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Offline coverage of RipeStatClient HTTP methods via a mocked handler (no real RIPE Stat calls).
public class RipeStatClientTests
{
    private static readonly IReadOnlyDictionary<string, (HttpStatusCode, string)> Endpoints =
        new Dictionary<string, (HttpStatusCode, string)>
        {
            ["as-overview"] =
                (HttpStatusCode.OK, """{"status":"ok","data":{"holder":"SENKO-AS Senko Digital","announced":true}}"""),
            ["announced-prefixes"] =
                (HttpStatusCode.OK, """{"status":"ok","data":{"prefixes":[{"prefix":"5.6.7.0/24"},{"prefix":"1.2.3.0/24"},{"prefix":"2001:db8::/32"}]}}"""),
            ["asn-neighbours"] =
                (HttpStatusCode.OK, """{"status":"ok","data":{"neighbours":[{"asn":100,"type":"left","power":9},{"asn":200,"type":"left","power":3},{"asn":300,"type":"right","power":1}]}}"""),
            ["searchcomplete"] =
                (HttpStatusCode.OK, """{"status":"ok","data":{"categories":[{"category":"ASNs","suggestions":[{"value":"AS213520","description":"SENKO-AS Senko"},{"value":"notanasn","description":"junk"}]}]}}"""),
            ["country-asns"] =
                (HttpStatusCode.OK, """{"status":"ok","data":{"countries":[{"resource":"FI","routed":[1,2,3]}]}}"""),
            ["rpki-validation"] =
                (HttpStatusCode.OK, """{"status":"ok","data":{"status":"valid"}}"""),
        };

    private static RipeStatClient Client(out TestHttpMessageHandler handler, RipeStatCache? cache = null)
    {
        handler = TestHttpMessageHandler.ByUrl(Endpoints);
        return new RipeStatClient(new HttpClient(handler), cache);
    }

    [Fact]
    public async Task GetAsnOverview_ParsesHolder()
    {
        var overview = await Client(out _).GetAsnOverviewAsync(64500);
        overview!.Holder.Should().Be("SENKO-AS Senko Digital");
        overview.Announced.Should().BeTrue();
    }

    [Fact]
    public async Task GetPrefixes_ReturnsIpv4Only_SortedNumerically()
    {
        var prefixes = await Client(out _).GetPrefixesAsync(64500);
        prefixes.Should().Equal("1.2.3.0/24", "5.6.7.0/24"); // IPv6 dropped, sorted by numeric key
    }

    [Fact]
    public async Task GetAllPrefixes_SplitsV4V6_AndCaches()
    {
        var dir = Directory.CreateTempSubdirectory();
        try
        {
            var cache = new RipeStatCache(dir.FullName);
            var client = Client(out var handler, cache);

            var (ok, v4, v6) = await client.GetAllPrefixesAsync(64500);
            ok.Should().BeTrue();
            v4.Should().Equal("1.2.3.0/24", "5.6.7.0/24");
            v6.Should().Equal("2001:db8::/32");

            // The second call uses the cache and sends no new HTTP request.
            int before = handler.Requests.Count;
            var (ok2, v4b, _) = await client.GetAllPrefixesAsync(64500);
            ok2.Should().BeTrue();
            v4b.Should().Equal("1.2.3.0/24", "5.6.7.0/24");
            handler.Requests.Count.Should().Be(before, "result came from cache");
        }
        finally { Directory.Delete(dir.FullName, true); }
    }

    [Fact]
    public async Task GetNeighbourCounts_CountsLeftAndRight()
    {
        var (up, down) = await Client(out _).GetNeighbourCountsAsync(64500);
        up.Should().Be(2);
        down.Should().Be(1);
    }

    [Fact]
    public async Task GetUpstreamAsns_ReturnsLeftByPowerDesc()
    {
        var ups = await Client(out _).GetUpstreamAsnsAsync(64500);
        ups.Should().Equal(100u, 200u); // "left" only, ordered by power desc
    }

    [Fact]
    public async Task GetCountryAsns_MatchesResourceCode()
    {
        var asns = await Client(out _).GetCountryAsnsAsync("FI");
        asns.Should().Equal(1u, 2u, 3u);
    }

    [Fact]
    public async Task Search_ParsesAsnSuggestions_SkipsJunk()
    {
        var results = await Client(out _).SearchAsync("senko");
        results.Should().ContainSingle();
        results[0].Asn.Should().Be(213520u);
        results[0].Description.Should().Be("SENKO-AS Senko");
    }

    [Fact]
    public async Task GetUpstreams_ResolvesHoldersInParallel()
    {
        var ups = await Client(out _).GetUpstreamsAsync(new uint[] { 100, 200 });
        ups.Should().HaveCount(2);
        ups.Should().OnlyContain(u => u.Description == "SENKO-AS Senko Digital");
    }

    [Fact]
    public async Task GetRpkiValidityRatio_ComputesRatioFromSamples()
    {
        var ratio = await Client(out _).GetRpkiValidityRatioAsync(64500, new[] { "1.2.3.0/24" });
        ratio.Should().Be(1.0, "the single sampled prefix returned status=valid");
    }

    [Fact]
    public async Task HttpError_DegradesGracefully()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.InternalServerError, "");
        var client = new RipeStatClient(new HttpClient(handler));

        (await client.GetAsnOverviewAsync(1)).Should().BeNull();
        (await client.GetPrefixesAsync(1)).Should().BeEmpty();
        (await client.GetCountryAsnsAsync("FI")).Should().BeEmpty();
        (await client.SearchAsync("x")).Should().BeEmpty();
        var (ok, _, _) = await client.GetAllPrefixesAsync(1);
        ok.Should().BeFalse("non-ok response must not be treated as authoritative empty");
    }

    [Fact]
    public async Task CallerCancellationIsNotConvertedToEmptyData()
    {
        var client = Client(out _);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await FluentActions.Invoking(() => client.GetAsnOverviewAsync(64500, cts.Token))
            .Should().ThrowAsync<OperationCanceledException>();
        await FluentActions.Invoking(() => client.GetNeighbourCountsAsync(64500, cts.Token))
            .Should().ThrowAsync<OperationCanceledException>();
        await FluentActions.Invoking(() => client.GetUpstreamAsnsAsync(64500, cts.Token))
            .Should().ThrowAsync<OperationCanceledException>();
        await FluentActions.Invoking(() => client.SearchAsync("test", cts.Token))
            .Should().ThrowAsync<OperationCanceledException>();
    }
}
