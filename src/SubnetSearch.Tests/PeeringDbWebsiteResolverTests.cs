using System.Net;
using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

// Authentication belongs to each PeeringDB request, not the shared client.
public class PeeringDbWebsiteResolverTests
{
    private static PeeringDbWebsiteResolver Client(TestHttpMessageHandler h, string? key = null)
        => new(new HttpClient(h), key);

    [Fact]
    public async Task GetNetworkInfo_KeyPresent_SendsApiKeyAuthorizationPerRequest()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"data":[]}""");
        await Client(handler, key: "K").GetNetworkInfoAsync(13335);

        var req = handler.Requests.Should().ContainSingle().Subject;
        req.Headers.Authorization.Should().NotBeNull("a configured key must be attached per-request");
        req.Headers.Authorization!.ToString().Should().Be("Api-Key K");
    }

    [Fact]
    public async Task GetNetworkInfo_KeyNull_SendsNoAuthorization()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"data":[]}""");
        await Client(handler).GetNetworkInfoAsync(13335); // key == null

        handler.Requests[0].Headers.Authorization.Should().BeNull(
            "no credential must be sent when no key is configured");
    }

    [Fact]
    public async Task GetNetworkInfo_KeyWithControlChars_IsSanitizedBeforeAttaching()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"data":[]}""");
        // CR, LF and null are header-injection vectors that must be stripped and the value trimmed.
        await Client(handler, key: "K\r\nX\0").GetNetworkInfoAsync(13335);

        handler.Requests[0].Headers.Authorization!.ToString().Should().Be("Api-Key KX");
    }

    [Fact]
    public async Task GetNetworkInfo_ParsesNetworkRecord()
    {
        const string json = """{"data":[{"id":1,"website":"http://x","info_type":"NSP","ix_count":3}]}""";
        var info = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, json))
            .GetNetworkInfoAsync(13335);

        info.Should().NotBeNull();
        info!.Website.Should().Be("http://x");
        info.NetId.Should().Be(1);
    }

    [Fact]
    public async Task GetNetworkInfo_EmptyData_ReturnsNull()
    {
        var info = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"data":[]}"""))
            .GetNetworkInfoAsync(64500);
        info.Should().BeNull();
    }

    [Fact]
    public async Task GetNetworkInfo_HttpError_ReturnsNull()
    {
        var info = await Client(TestHttpMessageHandler.Always(HttpStatusCode.InternalServerError, ""))
            .GetNetworkInfoAsync(64500);
        info.Should().BeNull("a failed PeeringDB call degrades to no enrichment");
    }

    [Fact]
    public async Task GetIxLocations_ParsesDedupesAndSorts()
    {
        const string json = """{"data":[{"name":"DE-CIX"},{"name":"AMS-IX"},{"name":"DE-CIX"}]}""";
        var ix = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, json)).GetIxLocationsAsync(7);
        ix.Should().Equal("AMS-IX", "DE-CIX");
    }

    [Fact]
    public async Task GetIxLocations_EmptyData_ReturnsNull()
    {
        var ix = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"data":[]}"""))
            .GetIxLocationsAsync(7);
        ix.Should().BeNull();
    }

    [Fact]
    public async Task IsAvailable_Success_ReturnsAvailable()
    {
        var status = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"data":[{"id":1}]}"""))
            .IsAvailableAsync();
        status.IsAvailable.Should().BeTrue();
    }

    [Fact]
    public async Task IsAvailable_ServerError_ReturnsUnavailable()
    {
        var status = await Client(TestHttpMessageHandler.Always(HttpStatusCode.BadGateway, ""))
            .IsAvailableAsync();
        status.IsAvailable.Should().BeFalse();
    }

    [Fact]
    public async Task IsAvailable_PreCancelledToken_SurfacesAsUnavailable() // edge case: external cancellation
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var status = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, "{}"))
            .IsAvailableAsync(cts.Token);

        // A pre-cancelled token must surface promptly (no hang) as a non-available status.
        status.IsAvailable.Should().BeFalse();
    }
}
