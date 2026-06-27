using System.Text.Json;

namespace SubnetSearch.Network.Reputation;

public class GreyNoiseClient(HttpClient http, string apiKey)
{
    public async Task<double?> GetMaliciousRatioAsync(
        IEnumerable<string> sampleIps, CancellationToken ct = default)
    {
        var ips = sampleIps.Take(3).ToList();
        if (ips.Count == 0) return null;
        int malicious = 0, total = 0;
        foreach (var ip in ips)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get,
                    $"https://api.greynoise.io/v3/community/{ip}");
                req.Headers.TryAddWithoutValidation("key", apiKey);
                using var resp = await http.SendAsync(req, ct);
                if (!resp.IsSuccessStatusCode) continue;
                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
                if (!doc.RootElement.TryGetProperty("classification", out var cls)) continue;
                total++;
                if (cls.GetString() == "malicious") malicious++;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { }
        }
        return total > 0 ? (double)malicious / total : null;
    }
}
