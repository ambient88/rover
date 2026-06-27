using System.Text.Json;

namespace SubnetSearch.Network.Reputation;

public class AbuseIpDbClient(HttpClient http, string apiKey)
{
    // AbuseIPDB free plan: 1 000 req/day. Serialize all requests to avoid burst.
    private readonly SemaphoreSlim _throttle = new(1, 1);

    public async Task<double?> GetBlockScoreAsync(string cidr, CancellationToken ct = default)
    {
        await _throttle.WaitAsync(ct);
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get,
                $"https://api.abuseipdb.com/api/v2/check-block?network={Uri.EscapeDataString(cidr)}&maxAgeInDays=30");
            // AbuseIPDB API v2 uses "Key" (not the conventional "X-API-Key").
            // See: https://docs.abuseipdb.com/#authentication
            req.Headers.TryAddWithoutValidation("Key", apiKey);
            req.Headers.TryAddWithoutValidation("Accept", "application/json");
            using var resp = await http.SendAsync(req, ct);
            if (!resp.IsSuccessStatusCode) return null;

            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            if (!doc.RootElement.TryGetProperty("data", out var data)) return null;
            if (!data.TryGetProperty("reportedAddress", out var arr)
                || arr.ValueKind != JsonValueKind.Array) return null;

            var scores = arr.EnumerateArray()
                .Where(e => e.TryGetProperty("abuseConfidenceScore", out _))
                .Select(e => e.GetProperty("abuseConfidenceScore").GetDouble())
                .ToList();
            return scores.Count > 0 ? scores.Average() : 0.0;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
        finally { _throttle.Release(); }
    }
}
