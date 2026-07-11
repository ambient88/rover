using System.Net;
using FluentAssertions;
using SubnetSearch.Network.Reputation;

namespace SubnetSearch.Tests;

// AbuseIPDB check-block: data.reportedAddress[].abuseConfidenceScore (0..100).
// Клиент возвращает среднее по адресам, 0.0 при пустом списке, null при сбое/отсутствии данных.
public class AbuseIpDbClientTests
{
    private static AbuseIpDbClient Client(TestHttpMessageHandler h)
        => new(new HttpClient(h), apiKey: "test-key");

    [Fact]
    public async Task GetBlockScore_AveragesReportedAddresses()
    {
        const string json = """
        {"data":{"reportedAddress":[
          {"ipAddress":"1.2.3.4","abuseConfidenceScore":100},
          {"ipAddress":"1.2.3.5","abuseConfidenceScore":50},
          {"ipAddress":"1.2.3.6","abuseConfidenceScore":0}
        ]}}
        """;
        var score = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, json))
            .GetBlockScoreAsync("1.2.3.0/24");

        score.Should().BeApproximately(50.0, 0.0001);
    }

    [Fact]
    public async Task GetBlockScore_EmptyReportedList_ReturnsZero()
    {
        const string json = """{"data":{"reportedAddress":[]}}""";
        var score = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, json))
            .GetBlockScoreAsync("8.8.8.0/24");

        score.Should().Be(0.0);
    }

    [Fact]
    public async Task GetBlockScore_SkipsEntriesWithoutScore()
    {
        const string json = """
        {"data":{"reportedAddress":[
          {"ipAddress":"1.2.3.4","abuseConfidenceScore":80},
          {"ipAddress":"1.2.3.5"}
        ]}}
        """;
        var score = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, json))
            .GetBlockScoreAsync("1.2.3.0/24");

        score.Should().Be(80.0, "запись без abuseConfidenceScore пропускается");
    }

    [Fact]
    public async Task GetBlockScore_NoDataProperty_ReturnsNull()
    {
        var score = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"errors":[]}"""))
            .GetBlockScoreAsync("1.2.3.0/24");

        score.Should().BeNull();
    }

    [Fact]
    public async Task GetBlockScore_ReportedAddressNotArray_ReturnsNull()
    {
        var score = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"data":{"reportedAddress":123}}"""))
            .GetBlockScoreAsync("1.2.3.0/24");

        score.Should().BeNull();
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task GetBlockScore_NonSuccessStatus_ReturnsNull(HttpStatusCode status)
    {
        var score = await Client(TestHttpMessageHandler.Always(status, "{}"))
            .GetBlockScoreAsync("1.2.3.0/24");

        score.Should().BeNull();
    }

    [Fact]
    public async Task GetBlockScore_MalformedJson_ReturnsNull() // краевой случай: битый ответ
    {
        var score = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, "{ not json ]"))
            .GetBlockScoreAsync("1.2.3.0/24");

        score.Should().BeNull();
    }

    [Fact]
    public async Task GetBlockScore_NetworkException_ReturnsNull() // краевой случай: обрыв соединения
    {
        var score = await Client(TestHttpMessageHandler.Throws(new HttpRequestException("connection reset")))
            .GetBlockScoreAsync("1.2.3.0/24");

        score.Should().BeNull();
    }

    [Fact]
    public async Task GetBlockScore_SendsApiKeyHeaderAndEscapedCidr()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"data":{"reportedAddress":[]}}""");
        await Client(handler).GetBlockScoreAsync("1.2.3.0/24");

        var req = handler.Requests.Should().ContainSingle().Subject;
        req.Headers.GetValues("Key").Should().ContainSingle().Which.Should().Be("test-key");
        req.RequestUri!.AbsoluteUri.Should().Contain("network=1.2.3.0%2F24", "CIDR URL-экранирован");
    }

    [Fact]
    public async Task GetBlockScore_Cancellation_Throws() // краевой случай: отмена операции
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var client = Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, "{}"));

        await client.Invoking(c => c.GetBlockScoreAsync("1.2.3.0/24", cts.Token))
            .Should().ThrowAsync<OperationCanceledException>();
    }
}
