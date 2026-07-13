using SubnetSearch.Core.Models.Network;

namespace SubnetSearch.Network.Http;

// Thin HTTP-probing adapter (live requests to remote hosts) — exercised by integration/manual
// runs, not unit tests; excluded from coverage so it doesn't skew the business-logic metric.
[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
public class HttpFingerprintService
{
    private static readonly TimeSpan FingerprintDeadline = TimeSpan.FromSeconds(6);
    private static readonly HttpClient _http = new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        // Allow expired certificates — they still carry fingerprinting information (issuer, SANs).
        // Reject certificates with no valid chain at all (e.g. self-signed without trust anchor)
        // to prevent MITM from injecting arbitrary headers into fingerprint results.
        ServerCertificateCustomValidationCallback = (_, _, _, errors) =>
            errors == System.Net.Security.SslPolicyErrors.None ||
            errors == System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors
    })
    {
        Timeout = TimeSpan.FromSeconds(5)
    };

    // Response headers that reveal proxy/CDN layers.
    private static readonly string[] ProxyIndicatorNames =
    [
        "via",            // RFC 7230: reveals proxy chain
        "x-cache",        // Varnish / CDN cache status
        "x-served-by",    // Fastly pop chain
        "x-cache-hits",   // Fastly cache hit count
        "cf-ray",         // Cloudflare request ID
        "x-amz-cf-id",    // AWS CloudFront request ID
        "x-amz-request-id", // S3/CloudFront
        "x-azure-ref",    // Azure CDN
        "x-fw-hash",      // Firewall / proxy hash
        "x-real-ip",      // Nginx upstream real IP (occasionally echoed)
        "x-forwarded-for",// Some servers echo this in responses
        "nel",            // Network Error Logging (Cloudflare / CDN)
        "report-to",      // Reporting API (Cloudflare uses this)
    ];

    private static IReadOnlyDictionary<string, string>? ExtractProxyHeaders(
        IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in headers)
        {
            if (ProxyIndicatorNames.Contains(h.Key, StringComparer.OrdinalIgnoreCase))
            {
                var val = string.Join(", ", h.Value);
                if (!string.IsNullOrWhiteSpace(val))
                    result[h.Key] = val;
            }
        }
        return result.Count > 0 ? result : null;
    }

    public async Task<HttpFingerprintResult?> FingerprintAsync(
        string host, CancellationToken ct = default)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(FingerprintDeadline);
        try
        {
            return await FingerprintCoreAsync(host, deadline.Token);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    private static async Task<HttpFingerprintResult?> FingerprintCoreAsync(
        string host,
        CancellationToken ct)
    {
        bool?   httpsRedirect = null;
        IEnumerable<KeyValuePair<string, IEnumerable<string>>>? headers = null;
        var tlsTask = TlsProbe.ProbeAsync(host, 443, ct);

        // UDP 2408 is useful only for IPs in ambiguous Cloudflare ranges.
        bool isAmbiguousRange = CloudflareProductDetector.DetectFromIp(host) == "Ambiguous";
        Task<bool?> udpTask = isAmbiguousRange
            ? UdpProbe.IsClosedAsync(host, 2408, 2000, ct).ContinueWith(
                t => (bool?)t.Result,
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default)
            : Task.FromResult<bool?>(null);

        try
        {
            using var resp = await _http.SendAsync(
                new HttpRequestMessage(HttpMethod.Head, $"https://{host}"), ct);
            headers = resp.Headers;
        }
        catch
        {
            try
            {
                using var resp = await _http.SendAsync(
                    new HttpRequestMessage(HttpMethod.Head, $"http://{host}"), ct);
                headers = resp.Headers;

                if ((int)resp.StatusCode is >= 300 and < 400)
                {
                    var location = resp.Headers.Location?.ToString() ?? "";
                    httpsRedirect = location.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
                }
            }
            catch { }
        }

        var (issuer, expiry, sans, tlsVersion) = await tlsTask;
        bool? udp2408Closed = isAmbiguousRange ? await udpTask : null;

        if (headers is null && issuer is null)
            return null;

        bool    httpResponded = headers is not null;
        string? cdn        = httpResponded ? CdnDetector.Detect(headers!) : null;
        string? cdnProduct = CloudflareProductDetector.Resolve(cdn, host, headers, httpResponded, udp2408Closed);
        string? server     = httpResponded ? CdnDetector.ExtractServer(headers!) : null;
        string? xPowered   = httpResponded ? CdnDetector.ExtractXPoweredBy(headers!) : null;
        bool?   expired    = expiry.HasValue ? expiry.Value < DateTime.UtcNow : null;
        var     proxyHdrs  = httpResponded ? ExtractProxyHeaders(headers!) : null;

        return new HttpFingerprintResult(
            CdnProvider:   cdn,
            CdnProduct:    cdnProduct,
            ServerHeader:  server,
            XPoweredBy:    xPowered,
            HttpsRedirect: httpsRedirect,
            TlsIssuer:     issuer,
            TlsExpiry:     expiry,
            TlsSans:       sans,
            TlsVersion:    tlsVersion,
            TlsExpired:    expired,
            ProxyHeaders:  proxyHdrs
        );
    }
}
