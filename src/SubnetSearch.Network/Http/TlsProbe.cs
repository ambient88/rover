using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace SubnetSearch.Network.Http;

// Probes a TLS handshake over a live socket and reads metadata from the real certificate.
// This requires integration or manual testing.
[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
internal static class TlsProbe
{
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(15);

    public static async Task<(string? Issuer, DateTime? Expiry, IReadOnlyList<string>? Sans, string? TlsVersion)>
        ProbeAsync(string host, int port = 443, CancellationToken ct = default)
    {
        try
        {
            using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            probeCts.CancelAfter(ProbeTimeout);

            using var tcp = new TcpClient();
            await tcp.ConnectAsync(host, port, probeCts.Token);

            await using var ssl = new SslStream(tcp.GetStream(), false,
                (_, _, _, _) => true);

            await ssl.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions { TargetHost = host }, probeCts.Token);

            // Dispose the certificate handle after reading its metadata. X509Certificate2.Dispose
            // is safe to call twice, so disposing the SslStream-owned instance here is harmless.
            using var cert = ssl.RemoteCertificate is X509Certificate2 existing
                ? existing
                : new X509Certificate2(ssl.RemoteCertificate!);

            return (
                ParseCn(cert.Issuer),
                cert.NotAfter.ToUniversalTime(),
                ParseSans(cert),
                ssl.SslProtocol.ToString()
            );
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return (null, null, null, null);
        }
    }

    private static string? ParseCn(string dn)
    {
        foreach (var part in dn.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return trimmed[3..];
        }
        return dn;
    }

    private static IReadOnlyList<string>? ParseSans(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value != "2.5.29.17") continue;
            var raw  = ext.Format(true);
            var sans = raw.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Trim())
                .Where(l => l.StartsWith("DNS Name=", StringComparison.OrdinalIgnoreCase))
                .Select(l => l["DNS Name=".Length..])
                .ToList();
            return sans.Count > 0 ? sans : null;
        }
        return null;
    }
}
