using System.Net;
using FluentAssertions;
using SubnetSearch.Network.Reputation;

namespace SubnetSearch.Tests;

// Covers the asynchronous IpapiIsClient HTTP path. IpapiIsClientTests cover parsing details.
public class IpapiIsClientHttpTests
{
    private static IpapiIsClient Client(TestHttpMessageHandler h) => new(new HttpClient(h));

    [Fact]
    public async Task GetAsnInfo_Success_ParsesResponse()
    {
        const string json = """{"asn":24940,"type":"hosting","abuser_score":"0.0100 (Low)"}""";
        var info = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, json)).GetAsnInfoAsync(24940);

        info.Type.Should().Be("hosting");
        info.AbuserScore.Should().BeApproximately(0.01, 0.00001);
    }

    [Fact]
    public async Task GetAsnInfo_UsesAsnQueryEndpoint()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"asn":13335,"type":"hosting"}""");
        await Client(handler).GetAsnInfoAsync(13335);

        handler.Requests[0].RequestUri!.AbsoluteUri.Should().Be("https://api.ipapi.is/?q=AS13335");
    }

    [Fact]
    public async Task GetAsnInfoForIp_UsesIpQueryEndpoint()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"ip":"1.1.1.1"}""");
        await Client(handler).GetAsnInfoForIpAsync("1.1.1.1");

        handler.Requests[0].RequestUri!.AbsoluteUri.Should().Be("https://api.ipapi.is/?q=1.1.1.1");
    }

    [Fact]
    public async Task GetAsnInfo_HttpError_ReturnsEmptyInfo()
    {
        var info = await Client(TestHttpMessageHandler.Always(HttpStatusCode.BadGateway, "502"))
            .GetAsnInfoAsync(24940);

        info.Should().Be(new AsnInfo(null, null));
    }

    [Fact]
    public async Task GetAsnInfo_NetworkException_ReturnsEmptyInfo()
    {
        var info = await Client(TestHttpMessageHandler.Throws(new HttpRequestException("dns failure")))
            .GetAsnInfoAsync(24940);

        info.Should().Be(new AsnInfo(null, null));
    }

    [Fact]
    public async Task GetAsnInfo_MalformedJson_ReturnsEmptyInfo()
    {
        var info = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, "{ not json ]"))
            .GetAsnInfoAsync(24940);

        info.Should().Be(new AsnInfo(null, null));
    }

    [Fact]
    public async Task GetAsnInfo_Cancellation_Throws()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var client = Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, "{}"));

        await client.Invoking(c => c.GetAsnInfoAsync(24940, cts.Token))
            .Should().ThrowAsync<OperationCanceledException>();
    }
}
