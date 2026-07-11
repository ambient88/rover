using System.Net;
using FluentAssertions;
using SubnetSearch.Network.Reputation;

namespace SubnetSearch.Tests;

// GreyNoise community: GET /v3/community/{ip} → {"classification":"malicious"|"benign"|...}.
// Клиент берёт до 3 IP и возвращает долю malicious среди ответивших, null если не ответил никто.
public class GreyNoiseClientTests
{
    private static GreyNoiseClient Client(TestHttpMessageHandler h)
        => new(new HttpClient(h), apiKey: "test-key");

    private static string Cls(string c) => $$"""{"classification":"{{c}}"}""";

    [Fact]
    public async Task GetMaliciousRatio_AllMalicious_ReturnsOne()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, Cls("malicious"));
        var ratio = await Client(handler).GetMaliciousRatioAsync(new[] { "1.1.1.1", "2.2.2.2", "3.3.3.3" });

        ratio.Should().Be(1.0);
    }

    [Fact]
    public async Task GetMaliciousRatio_MixedResults_ReturnsFraction()
    {
        var handler = TestHttpMessageHandler.ByUrl(new Dictionary<string, (HttpStatusCode, string)>
        {
            ["/1.1.1.1"] = (HttpStatusCode.OK, Cls("malicious")),
            ["/2.2.2.2"] = (HttpStatusCode.OK, Cls("benign")),
            ["/3.3.3.3"] = (HttpStatusCode.OK, Cls("benign")),
        });
        var ratio = await Client(handler).GetMaliciousRatioAsync(new[] { "1.1.1.1", "2.2.2.2", "3.3.3.3" });

        ratio.Should().BeApproximately(1.0 / 3.0, 0.0001);
    }

    [Fact]
    public async Task GetMaliciousRatio_TakesAtMostThreeIps()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, Cls("benign"));
        await Client(handler).GetMaliciousRatioAsync(new[] { "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5" });

        handler.Requests.Should().HaveCount(3, "клиент опрашивает максимум 3 IP");
    }

    [Fact]
    public async Task GetMaliciousRatio_EmptyInput_ReturnsNull() // краевой случай: пустой список
    {
        var ratio = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, Cls("benign")))
            .GetMaliciousRatioAsync(Array.Empty<string>());

        ratio.Should().BeNull();
    }

    [Fact]
    public async Task GetMaliciousRatio_AllRequestsFail_ReturnsNull() // краевой случай: никто не ответил
    {
        var ratio = await Client(TestHttpMessageHandler.Always(HttpStatusCode.Forbidden, "{}"))
            .GetMaliciousRatioAsync(new[] { "1.1.1.1", "2.2.2.2" });

        ratio.Should().BeNull("total == 0 → деление невозможно");
    }

    [Fact]
    public async Task GetMaliciousRatio_MissingClassification_SkipsEntry()
    {
        // 1.1.1.1 без поля classification (не учитывается), 2.2.2.2 malicious → total=1, malicious=1.
        var handler = TestHttpMessageHandler.ByUrl(new Dictionary<string, (HttpStatusCode, string)>
        {
            ["/1.1.1.1"] = (HttpStatusCode.OK, """{"ip":"1.1.1.1"}"""),
            ["/2.2.2.2"] = (HttpStatusCode.OK, Cls("malicious")),
        });
        var ratio = await Client(handler).GetMaliciousRatioAsync(new[] { "1.1.1.1", "2.2.2.2" });

        ratio.Should().Be(1.0);
    }

    [Fact]
    public async Task GetMaliciousRatio_PartialFailure_CountsOnlyResponders()
    {
        // 1.1.1.1 → 500 (пропуск), 2.2.2.2 → benign, 3.3.3.3 → malicious. total=2, malicious=1.
        var handler = TestHttpMessageHandler.ByUrl(new Dictionary<string, (HttpStatusCode, string)>
        {
            ["/1.1.1.1"] = (HttpStatusCode.InternalServerError, "{}"),
            ["/2.2.2.2"] = (HttpStatusCode.OK, Cls("benign")),
            ["/3.3.3.3"] = (HttpStatusCode.OK, Cls("malicious")),
        });
        var ratio = await Client(handler).GetMaliciousRatioAsync(new[] { "1.1.1.1", "2.2.2.2", "3.3.3.3" });

        ratio.Should().BeApproximately(0.5, 0.0001);
    }

    [Fact]
    public async Task GetMaliciousRatio_MalformedJson_SkipsEntry() // краевой случай: битый ответ
    {
        var handler = TestHttpMessageHandler.ByUrl(new Dictionary<string, (HttpStatusCode, string)>
        {
            ["/1.1.1.1"] = (HttpStatusCode.OK, "{ not json ]"),
            ["/2.2.2.2"] = (HttpStatusCode.OK, Cls("malicious")),
        });
        var ratio = await Client(handler).GetMaliciousRatioAsync(new[] { "1.1.1.1", "2.2.2.2" });

        ratio.Should().Be(1.0, "битый ответ пропущен, учтён только валидный malicious");
    }

    [Fact]
    public async Task GetMaliciousRatio_SendsKeyHeader()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, Cls("benign"));
        await Client(handler).GetMaliciousRatioAsync(new[] { "1.1.1.1" });

        handler.Requests[0].Headers.GetValues("key").Should().ContainSingle().Which.Should().Be("test-key");
    }

    [Fact]
    public async Task GetMaliciousRatio_Cancellation_Throws() // краевой случай: отмена
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var client = Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, Cls("benign")));

        await client.Invoking(c => c.GetMaliciousRatioAsync(new[] { "1.1.1.1" }, cts.Token))
            .Should().ThrowAsync<OperationCanceledException>();
    }
}
