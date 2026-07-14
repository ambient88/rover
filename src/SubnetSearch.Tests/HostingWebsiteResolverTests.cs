using FluentAssertions;
using SubnetSearch.Classification;
using System.Net;

namespace SubnetSearch.Tests;

// HostingWebsiteResolver.GetWebsite checks WHOIS, ASN, exact organization, exact manual override,
// substring manual override, and substring organization sources in that order.
public class HostingWebsiteResolverTests
{
    private sealed class AsyncHandler(
        Func<int, HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responder)
        : HttpMessageHandler
    {
        private int _requests;
        public int Requests => Volatile.Read(ref _requests);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            int requestNumber = Interlocked.Increment(ref _requests);
            return responder(requestNumber, request, cancellationToken);
        }
    }

    private static HostingWebsiteResolver Resolver(
        Dictionary<uint, string>? byAsn = null,
        Dictionary<string, string>? byOrg = null)
        => new(byAsn ?? new(), byOrg ?? new(StringComparer.OrdinalIgnoreCase), peeringDbResolver: null);

    [Fact]
    public void GetWebsite_WhoisWebsite_HasHighestPriority()
    {
        var r = Resolver(byAsn: new() { [1] = "https://from-asn" });

        r.GetWebsite(1, "AnyOrg", whoisWebsite: "https://from-whois")
            .Should().Be("https://from-whois");
    }

    [Fact]
    public void GetWebsite_ByAsn_ExactMatch()
        => Resolver(byAsn: new() { [24940] = "https://hetzner.example" })
            .GetWebsite(24940, null).Should().Be("https://hetzner.example");

    [Fact]
    public void GetWebsite_ByOrg_ExactMatch()
        => Resolver(byOrg: new(StringComparer.OrdinalIgnoreCase) { ["MyCorp"] = "https://mycorp.example" })
            .GetWebsite(null, "mycorp").Should().Be("https://mycorp.example", "byOrg регистронезависим");

    [Fact]
    public void GetWebsite_ManualOverride_ExactMatch()
        => Resolver().GetWebsite(null, "HETZNER").Should().Be("https://www.hetzner.com");

    [Fact]
    public void GetWebsite_ManualOverride_SubstringMatch()
        => Resolver().GetWebsite(null, "DigitalOcean, LLC")
            .Should().Be("https://www.digitalocean.com", "подстрока в имени организации");

    [Fact]
    public void GetWebsite_ByOrg_SubstringMatch()
        => Resolver(byOrg: new(StringComparer.OrdinalIgnoreCase) { ["ACME"] = "https://acme.example" })
            .GetWebsite(null, "The ACME Company").Should().Be("https://acme.example");

    [Fact]
    public void GetWebsite_PositiveSubstringResultIsMemoized()
    {
        var organizations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ACME"] = "https://acme.example"
        };
        var resolver = Resolver(byOrg: organizations);

        resolver.GetWebsite(null, "The ACME Company").Should().Be("https://acme.example");
        organizations.Clear();

        resolver.GetWebsite(null, "The ACME Company").Should().Be("https://acme.example");
    }

    [Fact]
    public void GetWebsite_NegativeSubstringResultIsMemoized()
    {
        var organizations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var resolver = Resolver(byOrg: organizations);

        resolver.GetWebsite(null, "The ACME Company").Should().BeNull();
        organizations["ACME"] = "https://acme.example";

        resolver.GetWebsite(null, "The ACME Company").Should().BeNull();
    }

    [Fact]
    public void GetWebsite_NoMatch_ReturnsNull()
        => Resolver().GetWebsite(999999, "Totally Unknown Provider").Should().BeNull();

    [Fact]
    public void GetWebsite_NullAsnAndOrg_ReturnsNull()
        => Resolver().GetWebsite(null, null).Should().BeNull();

    [Fact]
    public async Task GetNetworkInfo_NoPeeringDbResolver_ReturnsNull()
        => (await Resolver().GetNetworkInfoFromPeeringDbAsync(24940)).Should().BeNull();

    [Fact]
    public async Task GetIxLocations_NoPeeringDbResolver_ReturnsNull()
        => (await Resolver().GetIxLocationsAsync(24940)).Should().BeNull();

    [Fact]
    public async Task GetNetworkInfo_CallerCancellationStopsWaitingButKeepsSharedRequest()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new AsyncHandler(async (_, _, cancellationToken) =>
        {
            started.TrySetResult();
            await release.Task.WaitAsync(cancellationToken);
            return Json(HttpStatusCode.OK,
                """{"data":[{"id":1,"website":"https://example.com"}]}""");
        });
        var resolver = CreatePeeringDbResolver(handler, TimeSpan.FromSeconds(2));
        using var callerCancellation = new CancellationTokenSource();
        Task<SubnetSearch.Core.Models.Classification.PeeringDbNetworkInfo?> first =
            resolver.GetNetworkInfoFromPeeringDbAsync(64500, callerCancellation.Token);
        await started.Task;

        callerCancellation.Cancel();

        await FluentActions.Awaiting(() => first).Should().ThrowAsync<OperationCanceledException>();
        release.TrySetResult();
        var second = await resolver.GetNetworkInfoFromPeeringDbAsync(64500);
        second!.Website.Should().Be("https://example.com");
        handler.Requests.Should().Be(1);
    }

    [Fact]
    public async Task GetNetworkInfo_TransientFailureIsRetried()
    {
        var handler = new AsyncHandler((requestNumber, _, _) => Task.FromResult(
            requestNumber == 1
                ? Json(HttpStatusCode.ServiceUnavailable, "")
                : Json(HttpStatusCode.OK,
                    """{"data":[{"id":1,"website":"https://example.com"}]}""")));
        var resolver = CreatePeeringDbResolver(handler, TimeSpan.FromSeconds(1));

        (await resolver.GetNetworkInfoFromPeeringDbAsync(64500)).Should().BeNull();
        var retry = await resolver.GetNetworkInfoFromPeeringDbAsync(64500);

        retry!.Website.Should().Be("https://example.com");
        handler.Requests.Should().Be(2);
    }

    [Fact]
    public async Task GetNetworkInfo_UnderlyingTimeoutIsRetried()
    {
        var handler = new AsyncHandler(async (requestNumber, _, cancellationToken) =>
        {
            if (requestNumber == 1)
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return Json(HttpStatusCode.OK,
                """{"data":[{"id":1,"website":"https://example.com"}]}""");
        });
        var resolver = CreatePeeringDbResolver(handler, TimeSpan.FromMilliseconds(30));

        (await resolver.GetNetworkInfoFromPeeringDbAsync(64500)).Should().BeNull();
        var retry = await resolver.GetNetworkInfoFromPeeringDbAsync(64500);

        retry!.Website.Should().Be("https://example.com");
        handler.Requests.Should().Be(2);
    }

    [Fact]
    public async Task GetIxLocations_TransientFailureIsRetried()
    {
        int ixRequests = 0;
        var handler = new AsyncHandler((_, request, _) =>
        {
            if (request.RequestUri!.AbsolutePath.Contains("netixlan"))
            {
                ixRequests++;
                return Task.FromResult(ixRequests == 1
                    ? Json(HttpStatusCode.BadGateway, "")
                    : Json(HttpStatusCode.OK, """{"data":[{"name":"DE-CIX"}]}"""));
            }
            return Task.FromResult(Json(HttpStatusCode.OK,
                """{"data":[{"id":7,"website":"https://example.com"}]}"""));
        });
        var resolver = CreatePeeringDbResolver(handler, TimeSpan.FromSeconds(1));

        (await resolver.GetIxLocationsAsync(64500)).Should().BeNull();
        var retry = await resolver.GetIxLocationsAsync(64500);

        retry.Should().Equal("DE-CIX");
        handler.Requests.Should().Be(3);
    }

    private static HostingWebsiteResolver CreatePeeringDbResolver(
        HttpMessageHandler handler,
        TimeSpan timeout)
    {
        var peeringDb = new PeeringDbWebsiteResolver(new HttpClient(handler));
        return new HostingWebsiteResolver([], [], peeringDb, timeout);
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string json)
        => new(status)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
        };
}
