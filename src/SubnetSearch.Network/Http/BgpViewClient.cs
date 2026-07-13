using System.Text.Json;

namespace SubnetSearch.Network.Http;

// BGP routing data client for prefix discovery.
// Used as fallback when RIPE Stat returns no prefixes for an ASN.
// Rate limit: ~45 req/min — enforced via semaphore + inter-request delay.
public class BgpViewClient
{
    private readonly HttpClient _http;
    private readonly SemaphoreSlim _throttle = new(1, 1);
    private readonly TimeSpan _throttleDelay;
    private DateTimeOffset _nextRequestAt = DateTimeOffset.MinValue;
    private int _consecutiveFailures;
    private int _unavailable;
    private const int FailureThreshold = 2;
    private const int ThrottleDelayMs = 1_400; // ~42 req/min, safely under the 45 req/min cap
    private const int TimeoutMs       = 10_000;

    public BgpViewClient(HttpClient http)
        : this(http, TimeSpan.FromMilliseconds(ThrottleDelayMs))
    {
    }

    internal BgpViewClient(HttpClient http, TimeSpan throttleDelay)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _throttleDelay = throttleDelay;
    }

    // Ok = false means "the source failed" (HTTP error / timeout / malformed response):
    // empty lists when Ok = false are not an authoritative "no prefixes" (WR-01).
    public async Task<(bool Ok, IReadOnlyList<string> IPv4, IReadOnlyList<string> IPv6)> GetPrefixesAsync(
        uint asn, CancellationToken ct = default)
    {
        if (Volatile.Read(ref _unavailable) != 0) return (false, [], []);

        await _throttle.WaitAsync(ct);
        try
        {
            if (Volatile.Read(ref _unavailable) != 0) return (false, [], []);

            TimeSpan wait = _nextRequestAt - DateTimeOffset.UtcNow;
            if (wait > TimeSpan.Zero) await Task.Delay(wait, ct);
            _nextRequestAt = DateTimeOffset.UtcNow + _throttleDelay;

            using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            reqCts.CancelAfter(TimeoutMs);

            using var resp = await _http.GetAsync(
                $"https://api.bgpview.io/asn/{asn}/prefixes", reqCts.Token);

            if (!resp.IsSuccessStatusCode)
            {
                if (resp.StatusCode is System.Net.HttpStatusCode.BadRequest
                    or System.Net.HttpStatusCode.NotFound
                    or System.Net.HttpStatusCode.UnprocessableEntity)
                {
                    return (false, [], []);
                }

                if (resp.StatusCode == System.Net.HttpStatusCode.TooManyRequests &&
                    resp.Headers.RetryAfter?.Delta is { } retryAfter &&
                    retryAfter > _throttleDelay)
                {
                    _nextRequestAt = DateTimeOffset.UtcNow + retryAfter;
                }

                RecordFailure();
                return (false, [], []);
            }

            using var doc = JsonDocument.Parse(
                await resp.Content.ReadAsStringAsync(reqCts.Token));

            if (!doc.RootElement.TryGetProperty("data", out var data))
            {
                RecordFailure();
                return (false, [], []);
            }

            var ipv4 = ParsePrefixes(data, "ipv4_prefixes");
            var ipv6 = ParsePrefixes(data, "ipv6_prefixes");

            Volatile.Write(ref _consecutiveFailures, 0);
            return (true, ipv4, ipv6);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch
        {
            RecordFailure();
            return (false, [], []);
        }
        finally { _throttle.Release(); }
    }

    private void RecordFailure()
    {
        if (Interlocked.Increment(ref _consecutiveFailures) >= FailureThreshold)
            Interlocked.Exchange(ref _unavailable, 1);
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
