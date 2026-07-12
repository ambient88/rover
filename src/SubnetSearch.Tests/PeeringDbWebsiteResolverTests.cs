using System.Net;
using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

// Wave 0 (RED): locks the observable per-request auth contract of PeeringDbWebsiteResolver.
// The key travels on the individual HttpRequestMessage (Authorization: Api-Key <key>), never on
// the shared client's DefaultRequestHeaders. Key value is CR/LF/null-stripped and trimmed to
// prevent header injection. These tests intentionally reference the not-yet-existing 2-arg ctor
// (HttpClient, string?) and therefore fail to compile until plan 03-01 lands the implementation.
public class PeeringDbWebsiteResolverTests
{
    // RED driver: forces the (HttpClient, string? apiKey) ctor introduced in 03-01.
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
