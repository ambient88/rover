using System.Net;
using FluentAssertions;
using SubnetSearch.Network.Http;

namespace SubnetSearch.Tests;

// BgpViewClient parses ASN prefixes from api.bgpview.io. Ok=false indicates an HTTP or parsing failure,
// so an empty list is not treated as authoritative proof that no prefixes exist.
public class BgpViewClientTests
{
    private static BgpViewClient Client(TestHttpMessageHandler h) => new(new HttpClient(h));

    [Fact]
    public async Task GetPrefixes_Success_ParsesIpv4AndIpv6()
    {
        const string json = """
        {"data":{
          "ipv4_prefixes":[{"prefix":"1.2.3.0/24"},{"prefix":"5.6.0.0/16"}],
          "ipv6_prefixes":[{"prefix":"2001:db8::/32"}]
        }}
        """;
        var (ok, v4, v6) = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, json))
            .GetPrefixesAsync(13335);

        ok.Should().BeTrue();
        v4.Should().Equal("1.2.3.0/24", "5.6.0.0/16");
        v6.Should().Equal("2001:db8::/32");
    }

    [Fact]
    public async Task GetPrefixes_MissingIpv6_ReturnsEmptyList()
    {
        const string json = """{"data":{"ipv4_prefixes":[{"prefix":"1.0.0.0/8"}]}}""";
        var (ok, v4, v6) = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, json))
            .GetPrefixesAsync(1);

        ok.Should().BeTrue();
        v4.Should().Equal("1.0.0.0/8");
        v6.Should().BeEmpty();
    }

    [Fact]
    public async Task GetPrefixes_NonSuccess_ReturnsNotOk()
    {
        var (ok, v4, v6) = await Client(TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"))
            .GetPrefixesAsync(1);

        ok.Should().BeFalse();
        v4.Should().BeEmpty();
        v6.Should().BeEmpty();
    }

    [Fact]
    public async Task GetPrefixes_NoDataProperty_ReturnsNotOk()
    {
        var (ok, _, _) = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"status":"error"}"""))
            .GetPrefixesAsync(1);

        ok.Should().BeFalse();
    }

    [Fact]
    public async Task GetPrefixes_RepeatedFailuresOpenCircuit()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.TooManyRequests, "{}");
        var client = new BgpViewClient(new HttpClient(handler), TimeSpan.FromMilliseconds(50));

        await client.GetPrefixesAsync(1);
        await client.GetPrefixesAsync(2);
        await client.GetPrefixesAsync(3);

        handler.Requests.Should().HaveCount(2);
    }

    [Fact]
    public async Task GetPrefixes_RequestSpecificFailuresDoNotOpenCircuit()
    {
        int call = 0;
        var handler = TestHttpMessageHandler.Custom(_ =>
        {
            call++;
            return call < 3
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        "{\"data\":{\"ipv4_prefixes\":[{\"prefix\":\"1.0.0.0/8\"}]}}")
                };
        });
        var client = new BgpViewClient(new HttpClient(handler), TimeSpan.Zero);

        await client.GetPrefixesAsync(1);
        await client.GetPrefixesAsync(2);
        var result = await client.GetPrefixesAsync(3);

        handler.Requests.Should().HaveCount(3);
        result.Ok.Should().BeTrue();
        result.IPv4.Should().Equal("1.0.0.0/8");
    }

    [Fact]
    public async Task GetPrefixes_MalformedJson_ReturnsNotOk()
    {
        var (ok, _, _) = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, "{ broken"))
            .GetPrefixesAsync(1);

        ok.Should().BeFalse();
    }

    [Fact]
    public async Task GetPrefixes_SkipsEntriesWithoutPrefixField()
    {
        const string json = """{"data":{"ipv4_prefixes":[{"prefix":"1.0.0.0/8"},{"name":"no-prefix"}]}}""";
        var (ok, v4, _) = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, json))
            .GetPrefixesAsync(1);

        ok.Should().BeTrue();
        v4.Should().Equal("1.0.0.0/8");
    }

    [Fact]
    public async Task GetPrefixes_Cancellation_Throws()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, "{}"))
            .Invoking(c => c.GetPrefixesAsync(1, cts.Token))
            .Should().ThrowAsync<OperationCanceledException>();
    }
}
