using FluentAssertions;
using SubnetSearch.Network.Http;

namespace SubnetSearch.Tests;

public class CdnDetectorTests
{
    private static IEnumerable<KeyValuePair<string, IEnumerable<string>>> Headers(
        params (string Name, string Value)[] headers)
        => headers.Select(h =>
            new KeyValuePair<string, IEnumerable<string>>(h.Name, [h.Value]));

    [Theory]
    [InlineData("CF-Ray",        "abc123-AMS",   "Cloudflare")]
    [InlineData("X-Amz-Cf-Id",  "somevalue",    "CloudFront")]
    [InlineData("X-Varnish",     "123456",       "Varnish")]
    [InlineData("X-Sucuri-ID",   "abc",          "Sucuri WAF")]
    [InlineData("X-DDoS-Guard",  "1",            "DDoS-Guard")]
    public void Detect_IdentifiesCdnFromHeader(string header, string value, string expectedCdn)
    {
        var headers = Headers((header, value));
        CdnDetector.Detect(headers).Should().Be(expectedCdn);
    }

    [Theory]
    [InlineData("Server", "cloudflare",  "Cloudflare")]
    [InlineData("Server", "AkamaiGHost", "Akamai")]
    [InlineData("Server", "ddos-guard",  "DDoS-Guard")]
    public void Detect_IdentifiesCdnFromServerHeader(string header, string value, string expectedCdn)
    {
        var headers = Headers((header, value));
        CdnDetector.Detect(headers).Should().Be(expectedCdn);
    }

    [Fact]
    public void Detect_ReturnsNullWhenNoCdnHeaders()
    {
        var headers = Headers(("Content-Type", "text/html"), ("X-Custom", "value"));
        CdnDetector.Detect(headers).Should().BeNull();
    }

    [Fact]
    public void Detect_IsCaseInsensitiveForHeaderName()
    {
        var headers = Headers(("cf-ray", "abc123"));
        CdnDetector.Detect(headers).Should().Be("Cloudflare");
    }

    [Fact]
    public void ExtractServer_ReturnsServerHeaderValue()
    {
        var headers = Headers(("Server", "nginx/1.18.0"));
        CdnDetector.ExtractServer(headers).Should().Be("nginx/1.18.0");
    }

    [Fact]
    public void ExtractServer_ReturnsNullWhenAbsent()
    {
        var headers = Headers(("Content-Type", "text/html"));
        CdnDetector.ExtractServer(headers).Should().BeNull();
    }

    [Fact]
    public void ExtractXPoweredBy_ReturnsValue()
    {
        var headers = Headers(("X-Powered-By", "PHP/8.2"));
        CdnDetector.ExtractXPoweredBy(headers).Should().Be("PHP/8.2");
    }

    [Fact]
    public void ExtractXPoweredBy_ReturnsNullWhenAbsent()
    {
        var headers = Headers(("Server", "nginx"));
        CdnDetector.ExtractXPoweredBy(headers).Should().BeNull();
    }

    [Fact]
    public void Fastly_DetectedViaXServedBy()
    {
        var headers = Headers(("X-Served-By", "cache-ams21057-AMS"));
        CdnDetector.Detect(headers).Should().Be("Fastly");
    }

    [Fact]
    public void Varnish_DetectedViaViaHeader()
    {
        var headers = Headers(("Via", "1.1 varnish (Varnish/7.0)"));
        CdnDetector.Detect(headers).Should().Be("Varnish");
    }
}
