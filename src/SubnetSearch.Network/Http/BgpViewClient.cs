using System.Text.Json;

namespace SubnetSearch.Network.Http;

// BGP routing data client for prefix discovery.
// Used as fallback when RIPE Stat returns no prefixes for an ASN.
// Rate limit: ~45 req/min — enforced via semaphore + inter-request delay.
public class BgpViewClient(HttpClient http)
{
    private readonly SemaphoreSlim _throttle = new(1, 1);
    private const int ThrottleDelayMs = 1_400; // ~42 req/min, safely under the 45 req/min cap
    private const int TimeoutMs       = 10_000;

    public async Task<(IReadOnlyList<string> IPv4, IReadOnlyList<string> IPv6)> GetPrefixesAsync(
        uint asn, CancellationToken ct = default)
    {
        await _throttle.WaitAsync(ct);
        try
        {
            using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            reqCts.CancelAfter(TimeoutMs);

            using var resp = await http.GetAsync(
                $"https://api.bgpview.io/asn/{asn}/prefixes", reqCts.Token);

            if (!resp.IsSuccessStatusCode) return ([], []);

            using var doc = JsonDocument.Parse(
                await resp.Content.ReadAsStringAsync(reqCts.Token));

            if (!doc.RootElement.TryGetProperty("data", out var data)) return ([], []);

            var ipv4 = ParsePrefixes(data, "ipv4_prefixes");
            var ipv6 = ParsePrefixes(data, "ipv6_prefixes");

            await Task.Delay(ThrottleDelayMs, ct);
            return (ipv4, ipv6);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return ([], []); } // timeout or parse error — caller falls through
        finally { _throttle.Release(); }
    }

    private static IReadOnlyList<string> ParsePrefixes(JsonElement data, string key)
    {
        if (!data.TryGetProperty(key, out var arr) || arr.ValueKind != JsonValueKind.Array)
            return [];

        var result = new List<string>();
        foreach (var item in arr.EnumerateArray())
        {
            if (item.TryGetProperty("prefix", out var p))
            {
                var s = p.GetString();
                if (!string.IsNullOrEmpty(s)) result.Add(s);
            }
        }
        return result;
    }
}
