using System.Net;
using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Network.Http;

namespace SubnetSearch.Tests;

// The shared client must not expose PeeringDB credentials to other services.
public class HttpClientHeaderBleedTests
{
    [Fact]
    public void CreatePeeringDbHttpClient_KeepsUserAgent_ButSetsNoDefaultAuthorization()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "{}");
        var client = ClassifierFactory.CreatePeeringDbHttpClient(new HttpClient(handler));

        client.DefaultRequestHeaders.Authorization.Should().BeNull(
            "the PeeringDB key must travel per-request, never on the shared client's default headers");
        client.DefaultRequestHeaders.UserAgent.ToString().Should().Contain("rover",
            "the neutral User-Agent is not a secret and must be preserved");
    }

    [Fact]
    public async Task SharedClient_DoesNotLeakKey_ToNeighbourService()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"data":{"ipv4_prefixes":[]}}""");
        // Build the shared client the same way production does, then hand it to a no-auth neighbour.
        var shared = ClassifierFactory.CreatePeeringDbHttpClient(new HttpClient(handler));
        var neighbour = new BgpViewClient(shared);

        await neighbour.GetPrefixesAsync(13335);

        handler.Requests[0].Headers.Authorization.Should().BeNull(
            "shared client must not leak the PeeringDB key to unrelated services");
    }
}
