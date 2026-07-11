using System.Net;
using FluentAssertions;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Network;

namespace SubnetSearch.Tests;

// TracerouteAnalyzer: классификация хопов (Normal/ProxyCdn/Timeout), детект скрытого маршрута
// (значимый хвост таймаутов после CDN-хопа). PTR резолвится через инъецируемый IDnsResolver.
public class TracerouteAnalyzerTests
{
    private sealed class StubDns : IDnsResolver
    {
        private readonly IReadOnlyDictionary<string, string?> _ptr;
        public StubDns(IReadOnlyDictionary<string, string?> ptr) => _ptr = ptr;

        public Task<IReadOnlyList<IPAddress>> ResolveAllIpAsync(string domain, CancellationToken ct = default)
            => Task.FromResult((IReadOnlyList<IPAddress>)Array.Empty<IPAddress>());

        public Task<string?> ReverseDnsAsync(IPAddress ip, CancellationToken ct = default)
            => Task.FromResult(_ptr.TryGetValue(ip.ToString(), out var p) ? p : null);
    }

    private static TracerouteHop Hop(int n, string? ip, string? ptr = null)
        => new(n, ip, ptr, ip == null ? null : 10.0);

    [Fact]
    public async Task Analyze_EmptyHops_ReturnsEmptyAnalysis() // краевой случай: пустой трейс
    {
        var result = await TracerouteAnalyzer.AnalyzeAsync(
            Array.Empty<TracerouteHop>(), new StubDns(new Dictionary<string, string?>()));

        result.Hops.Should().BeEmpty();
        result.LikelyHiddenRoute.Should().BeFalse();
        result.TrailingTimeouts.Should().Be(0);
        result.HiddenBehind.Should().BeNull();
    }

    [Fact]
    public async Task Analyze_NormalRoute_AllHopsNormal()
    {
        var hops = new[] { Hop(1, "192.0.2.1"), Hop(2, "8.8.8.8") };
        var dns = new StubDns(new Dictionary<string, string?>
        {
            ["192.0.2.1"] = "gw.example.net",
            ["8.8.8.8"]   = "dns.google",
        });

        var result = await TracerouteAnalyzer.AnalyzeAsync(hops, dns);

        result.Hops.Should().OnlyContain(h => h.Kind == HopKind.Normal);
        result.LikelyHiddenRoute.Should().BeFalse();
    }

    [Fact]
    public async Task Analyze_CdnPtr_ClassifiedAsProxyCdn()
    {
        var hops = new[] { Hop(1, "23.32.1.1") };
        var dns = new StubDns(new Dictionary<string, string?>
        {
            ["23.32.1.1"] = "a23-32-1-1.deploy.static.akamaitechnologies.com",
        });

        var result = await TracerouteAnalyzer.AnalyzeAsync(hops, dns);

        var hop = result.Hops.Should().ContainSingle().Subject;
        hop.Kind.Should().Be(HopKind.ProxyCdn);
        hop.ProxyHint.Should().Be("Akamai");
    }

    [Fact]
    public async Task Analyze_CloudflareIpRange_DetectedWithoutPtr()
    {
        // 104.18.0.1 попадает в диапазон Cloudflare Workers/Pages — детект по IP, не по PTR.
        var hops = new[] { Hop(1, "104.18.0.1") };
        var result = await TracerouteAnalyzer.AnalyzeAsync(hops, new StubDns(new Dictionary<string, string?>()));

        var hop = result.Hops.Should().ContainSingle().Subject;
        hop.Kind.Should().Be(HopKind.ProxyCdn);
        hop.ProxyHint.Should().Contain("Cloudflare");
    }

    [Fact]
    public async Task Analyze_TimeoutHops_ClassifiedAsTimeout()
    {
        var hops = new[] { Hop(1, "8.8.8.8"), Hop(2, null), Hop(3, null) };
        var dns = new StubDns(new Dictionary<string, string?> { ["8.8.8.8"] = "dns.google" });

        var result = await TracerouteAnalyzer.AnalyzeAsync(hops, dns);

        result.Hops[1].Kind.Should().Be(HopKind.Timeout);
        result.Hops[2].Kind.Should().Be(HopKind.Timeout);
        result.TrailingTimeouts.Should().Be(2);
    }

    [Fact]
    public async Task Analyze_HiddenRoute_CdnFollowedByTrailingTimeouts()
    {
        // Последний видимый хоп — Cloudflare-CDN, за ним ≥3 таймаута → маршрут «спрятан за CDN».
        var hops = new[]
        {
            Hop(1, "192.0.2.1"),
            Hop(2, "104.18.0.1"),  // Cloudflare
            Hop(3, null),
            Hop(4, null),
            Hop(5, null),
        };
        var dns = new StubDns(new Dictionary<string, string?> { ["192.0.2.1"] = "gw.local" });

        var result = await TracerouteAnalyzer.AnalyzeAsync(hops, dns);

        result.LikelyHiddenRoute.Should().BeTrue();
        result.TrailingTimeouts.Should().Be(3);
        result.HiddenBehind.Should().Contain("Cloudflare");
    }

    [Fact]
    public async Task Analyze_TrailingTimeoutsWithoutCdn_NotHidden()
    {
        // Хвост таймаутов есть, но последний видимый хоп — обычный → не считается скрытым.
        var hops = new[] { Hop(1, "8.8.8.8"), Hop(2, null), Hop(3, null), Hop(4, null) };
        var dns = new StubDns(new Dictionary<string, string?> { ["8.8.8.8"] = "dns.google" });

        var result = await TracerouteAnalyzer.AnalyzeAsync(hops, dns);

        result.LikelyHiddenRoute.Should().BeFalse();
        result.HiddenBehind.Should().BeNull();
    }
}
