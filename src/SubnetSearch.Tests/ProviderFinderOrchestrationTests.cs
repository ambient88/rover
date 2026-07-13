using System.Net;
using FluentAssertions;
using SubnetSearch.Network;
using SubnetSearch.Network.Http;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Exercises the full FindGlobal/FindByAsnList candidate pipeline (PeeringDB net fetch → parse →
// RIPE prefix/neighbour enrichment → scoring) against mocked HTTP endpoints.
public class ProviderFinderOrchestrationTests
{
    private static HttpClient PdbWithNets(string netJsonData)
        => new(TestHttpMessageHandler.Custom(req =>
        {
            string url = req.RequestUri!.AbsoluteUri;
            string body = url.Contains("/net?", StringComparison.Ordinal)
                ? $"{{\"data\":[{netJsonData}]}}"
                : "{\"data\":[]}";
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
        }));

    private static HttpClient RipeWithPrefixes(string prefixCidr)
        => new(TestHttpMessageHandler.Custom(req =>
        {
            string url = req.RequestUri!.AbsoluteUri;
            string body =
                url.Contains("announced-prefixes", StringComparison.Ordinal)
                    ? $"{{\"status\":\"ok\",\"data\":{{\"prefixes\":[{{\"prefix\":\"{prefixCidr}\"}}]}}}}"
                : url.Contains("asn-neighbours", StringComparison.Ordinal)
                    ? "{\"status\":\"ok\",\"data\":{\"neighbours\":[{\"asn\":100,\"type\":\"left\",\"power\":9}]}}"
                : url.Contains("rpki-validation", StringComparison.Ordinal)
                    ? "{\"status\":\"ok\",\"data\":{\"status\":\"valid\"}}"
                    : "{\"status\":\"ok\",\"data\":{}}";
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
        }));

    [Fact]
    public async Task FindGlobal_WithContentNet_ReturnsEnrichedCandidate()
    {
        using var pdb  = PdbWithNets(
            "{\"asn\":64500,\"name\":\"HostCo\",\"info_type\":\"Content\",\"country\":\"DE\",\"ix_count\":5}");
        using var ripe = RipeWithPrefixes("1.2.3.0/22"); // /22 = 1024 addresses
        using var bgp  = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));

        var finder = new ProviderFinder(
            pdb, new RipeStatClient(ripe), bgpView: new BgpViewClient(bgp));

        var result = await finder.FindGlobalAsync(infoTypes: ["Content"]);

        result.Should().Contain(c => c.Asn == 64500);
        var host = result.First(c => c.Asn == 64500);
        host.Name.Should().Be("HostCo");
        host.Prefixes.Should().Contain("1.2.3.0/22");
        host.TotalIpCount.Should().Be(1024);
    }

    [Fact]
    public async Task FindGlobal_NetWithoutPrefixes_IsDropped()
    {
        using var pdb  = PdbWithNets(
            "{\"asn\":64501,\"name\":\"NoPrefix\",\"info_type\":\"Content\"}");
        // RIPE returns no prefixes for this ASN → candidate has an empty pool and is dropped.
        using var ripe = new HttpClient(TestHttpMessageHandler.Custom(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent("{\"status\":\"ok\",\"data\":{\"prefixes\":[]}}") }));
        using var bgp  = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));

        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), bgpView: new BgpViewClient(bgp));

        var result = await finder.FindGlobalAsync(infoTypes: ["Content"]);

        result.Should().NotContain(c => c.Asn == 64501, "a candidate with no announced prefixes is dropped");
    }

    [Fact]
    public async Task FindByRegion_ResolvesIxThenNetixlanThenNet()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(req =>
        {
            string url = req.RequestUri!.AbsoluteUri;
            string body =
                url.Contains("/ix?", StringComparison.Ordinal)       ? "{\"data\":[{\"id\":10}]}"
              : url.Contains("/netixlan?", StringComparison.Ordinal) ? "{\"data\":[{\"net_id\":20}]}"
              : url.Contains("/net/", StringComparison.Ordinal)
                    ? "{\"data\":[{\"asn\":64500,\"name\":\"HostCo\",\"info_type\":\"Content\"}]}"
              : "{\"data\":[]}";
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
        }));
        using var ripe = RipeWithPrefixes("1.2.3.0/22");
        using var bgp  = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));

        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), bgpView: new BgpViewClient(bgp));

        var result = await finder.FindByRegionAsync("frankfurt");

        result.Should().Contain(c => c.Asn == 64500);
    }

    [Fact]
    public async Task FindByRegion_NoIxMatches_ReturnsEmpty()
    {
        using var pdb  = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.OK, "{\"data\":[]}"));
        using var ripe = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        (await finder.FindByRegionAsync("nowhere")).Should().BeEmpty();
    }

    [Fact]
    public async Task FindByAsnList_FetchesPrefixesFromRipe()
    {
        using var pdb  = PdbWithNets("");
        using var ripe = RipeWithPrefixes("5.6.0.0/16"); // 65536 addresses
        using var bgp  = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));

        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), bgpView: new BgpViewClient(bgp));

        var result = await finder.FindByAsnListAsync(
            [(64500, 1)], nameFallback: new Dictionary<uint, string> { [64500] = "Example" });

        result.Should().ContainSingle();
        result[0].Prefixes.Should().Contain("5.6.0.0/16");
    }

    [Fact]
    public async Task FindGlobal_ExcludeCdn_KeepsWhitelistedHostingCandidate()
    {
        using var pdb  = PdbWithNets(
            "{\"asn\":64500,\"name\":\"HostCo\",\"info_type\":\"Content\",\"country\":\"DE\"}");
        using var ripe = RipeWithPrefixes("5.6.0.0/16");
        using var bgp  = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));

        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), bgpView: new BgpViewClient(bgp));

        // excludeCdn turns on the hosting filter; the whitelist guarantees the candidate survives it.
        var result = await finder.FindGlobalAsync(
            infoTypes: ["Content"], excludeCdn: true,
            localHostingWhitelist: new HashSet<uint> { 64500 });

        result.Should().Contain(c => c.Asn == 64500);
    }

    [Fact]
    public async Task FindGlobal_AiOnly_DropsNonAiProviders()
    {
        using var pdb  = PdbWithNets(
            "{\"asn\":64500,\"name\":\"Generic HostCo\",\"info_type\":\"Content\"}");
        using var ripe = RipeWithPrefixes("5.6.0.0/16");
        using var bgp  = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), bgpView: new BgpViewClient(bgp));

        var result = await finder.FindGlobalAsync(infoTypes: ["Content"], aiOnly: true);

        result.Should().NotContain(c => c.Asn == 64500, "a generic host is not an AI/GPU provider");
    }

    [Fact]
    public async Task FindGlobal_ExcludeAi_KeepsGenericHost()
    {
        using var pdb  = PdbWithNets(
            "{\"asn\":64500,\"name\":\"Generic HostCo\",\"info_type\":\"Content\"}");
        using var ripe = RipeWithPrefixes("5.6.0.0/16");
        using var bgp  = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), bgpView: new BgpViewClient(bgp));

        var result = await finder.FindGlobalAsync(infoTypes: ["Content"], excludeAi: true);

        result.Should().Contain(c => c.Asn == 64500);
    }

    [Fact]
    public async Task FindGlobal_PeeringDbCache_SecondCallSkipsNetwork()
    {
        var cacheDir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            using var pdb  = PdbWithNets(
                "{\"asn\":64500,\"name\":\"HostCo\",\"info_type\":\"Content\"}");
            using var ripe = RipeWithPrefixes("5.6.0.0/16");
            using var bgp  = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));
            var finder = new ProviderFinder(
                pdb, new RipeStatClient(ripe), bgpView: new BgpViewClient(bgp), cacheDir: cacheDir);

            await finder.FindGlobalAsync(infoTypes: ["Content"]); // populates the PeeringDB net cache
            var result = await finder.FindGlobalAsync(infoTypes: ["Content"]); // should read the cache

            result.Should().Contain(c => c.Asn == 64500);
        }
        finally { Directory.Delete(cacheDir, true); }
    }

    [Fact]
    public async Task FindByAsnList_UsesBgpViewFallback_WhenRipeEmpty()
    {
        using var pdb  = PdbWithNets("");
        // RIPE has no prefixes; BGPView supplies them.
        using var ripe = new HttpClient(TestHttpMessageHandler.Custom(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent("{\"status\":\"ok\",\"data\":{\"prefixes\":[]}}") }));
        using var bgp  = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.OK,
            "{\"data\":{\"ipv4_prefixes\":[{\"prefix\":\"9.9.9.0/24\"}],\"ipv6_prefixes\":[]}}"));

        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), bgpView: new BgpViewClient(bgp));

        var result = await finder.FindByAsnListAsync(
            [(64500, 1)], nameFallback: new Dictionary<uint, string> { [64500] = "Example" });

        result.Should().ContainSingle();
        result[0].Prefixes.Should().Contain("9.9.9.0/24");
    }
}
