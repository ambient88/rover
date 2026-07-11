using FluentAssertions;
using SubnetSearch.Network.Http;

namespace SubnetSearch.Tests;

// CloudflareProductDetector: определение продукта CF по диапазонам IP, заголовкам и
// комбинации UDP/HTTP-сигналов (WARP vs Tunnel vs CDN).
public class CloudflareProductDetectorTests
{
    private static KeyValuePair<string, IEnumerable<string>>[] Headers(params (string, string)[] hs)
        => hs.Select(h => new KeyValuePair<string, IEnumerable<string>>(h.Item1, new[] { h.Item2 })).ToArray();

    // ── DetectFromIp ──

    [Theory]
    [InlineData("104.18.5.5",   "Cloudflare Workers/Pages")]
    [InlineData("104.19.1.1",   "Cloudflare Workers/Pages")]
    [InlineData("198.41.200.7", "Cloudflare Tunnel")]
    [InlineData("188.114.96.1", "Ambiguous")]
    public void DetectFromIp_KnownRanges(string ip, string expected)
        => CloudflareProductDetector.DetectFromIp(ip).Should().Be(expected);

    [Fact]
    public void DetectFromIp_OutsideRanges_ReturnsNull()
        => CloudflareProductDetector.DetectFromIp("8.8.8.8").Should().BeNull();

    [Fact]
    public void DetectFromIp_InvalidIp_ReturnsNull() // краевой случай: не IP
        => CloudflareProductDetector.DetectFromIp("not-an-ip").Should().BeNull();

    // ── DetectFromHeaders ──

    [Fact]
    public void DetectFromHeaders_CfWorker_ReturnsWorkers()
        => CloudflareProductDetector.DetectFromHeaders(Headers(("CF-Worker", "example.com")))
            .Should().Be("Cloudflare Workers");

    [Fact]
    public void DetectFromHeaders_CdnSignature_ReturnsCdn()
        => CloudflareProductDetector.DetectFromHeaders(
                Headers(("Server", "cloudflare"), ("NEL", "{}"), ("Report-To", "{}")))
            .Should().Be("Cloudflare CDN");

    [Fact]
    public void DetectFromHeaders_ServerWithoutNel_ReturnsNull()
        => CloudflareProductDetector.DetectFromHeaders(Headers(("Server", "cloudflare")))
            .Should().BeNull();

    [Fact]
    public void DetectFromHeaders_NoCloudflareSignals_ReturnsNull()
        => CloudflareProductDetector.DetectFromHeaders(Headers(("Server", "nginx")))
            .Should().BeNull();

    // ── Resolve: приоритеты сигналов ──

    [Fact]
    public void Resolve_NotCloudflare_ReturnsNull()
        => CloudflareProductDetector.Resolve("Akamai", "104.18.0.1", null).Should().BeNull();

    [Fact]
    public void Resolve_HeaderSignal_WinsOverIp()
        => CloudflareProductDetector.Resolve("Cloudflare", "104.18.0.1", Headers(("CF-Worker", "x")))
            .Should().Be("Cloudflare Workers");

    [Fact]
    public void Resolve_UnambiguousIpRange_ReturnsProduct()
        => CloudflareProductDetector.Resolve("Cloudflare", "104.18.0.1", null)
            .Should().Be("Cloudflare Workers/Pages");

    [Fact]
    public void Resolve_AmbiguousRange_Udp2408Closed_HttpResponds_IsTunnel()
        => CloudflareProductDetector.Resolve("Cloudflare", "188.114.96.1", null,
                httpResponded: true, udp2408Closed: true)
            .Should().Be("Cloudflare Tunnel");

    [Fact]
    public void Resolve_AmbiguousRange_Udp2408Open_NoHttp_IsWarp()
        => CloudflareProductDetector.Resolve("Cloudflare", "188.114.96.1", null,
                httpResponded: false, udp2408Closed: false)
            .Should().Be("Cloudflare WARP");

    [Fact]
    public void Resolve_AmbiguousRange_Udp2408Open_HttpResponds_IsTunnel()
        => CloudflareProductDetector.Resolve("Cloudflare", "188.114.96.1", null,
                httpResponded: true, udp2408Closed: false)
            .Should().Be("Cloudflare Tunnel");

    [Fact]
    public void Resolve_AmbiguousRange_UdpUnknown_HttpUnknown_IsTunnelOrWarp()
        => CloudflareProductDetector.Resolve("Cloudflare", "188.114.96.1", null)
            .Should().Be("Cloudflare Tunnel/WARP");

    [Fact]
    public void Resolve_CloudflareButNoIpMatch_FallsBackToCdn()
        => CloudflareProductDetector.Resolve("Cloudflare", "8.8.8.8", null)
            .Should().Be("Cloudflare CDN");
}
