using FluentAssertions;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

// ResolveAsync orchestration over a stubbed WHOIS exchange: IANA referral routing,
// per-IP caching, and the fail-soft error contract (null instead of exceptions).
public class WhoisResolverResolveTests
{
    private const string ArinBody = """
        OrgName:        Example Hosting Inc.
        Country:        US
        """;

    [Fact]
    public void DefaultCtor_WiresTheRealWhoisTransport()
    {
        // Construction only: the socket transport is exercised by integration runs.
        new WhoisResolver().Should().NotBeNull();
    }

    [Fact]
    public async Task Resolve_FollowsIanaReferral()
    {
        var servers = new List<string>();
        var resolver = new WhoisResolver((server, query, ct) =>
        {
            servers.Add(server);
            return Task.FromResult(server == "whois.iana.org"
                ? "refer: whois.arin.net"
                : ArinBody);
        });

        var result = await resolver.ResolveAsync("8.8.8.8");

        servers.Should().Equal("whois.iana.org", "whois.arin.net");
        result!.Organization.Should().Be("Example Hosting Inc.");
        result.Rir.Should().Be("ARIN");
    }

    [Fact]
    public async Task Resolve_NoReferral_DefaultsToRipe()
    {
        var servers = new List<string>();
        var resolver = new WhoisResolver((server, query, ct) =>
        {
            servers.Add(server);
            return Task.FromResult(server == "whois.iana.org"
                ? "no referral in this response"
                : "org-name: RIPE Org\ncountry: NL");
        });

        var result = await resolver.ResolveAsync("9.9.9.9");

        servers[1].Should().Be("whois.ripe.net");
        result!.Organization.Should().Be("RIPE Org");
    }

    [Fact]
    public async Task Resolve_SameIp_IsCachedAcrossCalls()
    {
        int exchanges = 0;
        var resolver = new WhoisResolver((server, query, ct) =>
        {
            exchanges++;
            return Task.FromResult(server == "whois.iana.org" ? "refer: whois.arin.net" : ArinBody);
        });

        await resolver.ResolveAsync("8.8.8.8");
        await resolver.ResolveAsync("8.8.8.8");

        exchanges.Should().Be(2, "one IANA plus one RIR exchange, reused from the cache afterwards");
    }

    [Fact]
    public async Task Resolve_NetworkFailure_ReturnsNull()
    {
        var resolver = new WhoisResolver(
            (server, query, ct) => throw new IOException("connection reset"));

        (await resolver.ResolveAsync("8.8.8.8")).Should().BeNull();
    }

    [Fact]
    public async Task Resolve_InternalTimeout_ReturnsNull()
    {
        // The stub never answers; the resolver's own 3-second budget must expire and fail soft.
        var resolver = new WhoisResolver(async (server, query, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return "";
        });

        (await resolver.ResolveAsync("8.8.8.8")).Should().BeNull();
    }
}
