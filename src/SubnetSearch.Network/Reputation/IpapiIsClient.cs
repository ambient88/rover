using System.Text.Json;

namespace SubnetSearch.Network.Reputation;

// ipapi.is returns both abuse score and ASN type in a single request.
public record AsnInfo(double? AbuserScore, string? Type);

public class IpapiIsClient(HttpClient http)
{
    // ipapi.is free plan: 1 000 req/day. Limit concurrent requests to avoid burst.
    private readonly SemaphoreSlim _throttle = new(3, 3);

    // Fetches both abuser_score and ASN type in one request.
    // type values: "hosting", "isp", "business", "education", "government", "inactive"
    public async Task<AsnInfo> GetAsnInfoAsync(uint asn, CancellationToken ct = default)
    {
        bool acquired = false;
        try
        {
            await _throttle.WaitAsync(ct);
            acquired = true;
            var json = await http.GetStringAsync($"https://ipapi.is/json/?asn=AS{asn}", ct);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("asn", out var asnEl))
                return new AsnInfo(null, null);

            double? abuserScore = null;
            if (asnEl.TryGetProperty("abuser_score", out var scoreEl))
            {
                if (scoreEl.ValueKind == JsonValueKind.Number)
                    abuserScore = scoreEl.GetDouble();
                else if (scoreEl.ValueKind == JsonValueKind.String
                         && double.TryParse(scoreEl.GetString(),
                             System.Globalization.NumberStyles.Float,
                             System.Globalization.CultureInfo.InvariantCulture, out var parsed))
                    abuserScore = parsed;
            }

            string? type = asnEl.TryGetProperty("type", out var typeEl) ? typeEl.GetString() : null;
            return new AsnInfo(abuserScore, type);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return new AsnInfo(null, null); }
        finally { if (acquired) _throttle.Release(); }
    }

    // Backward-compatible wrapper used by ProviderScorer.
    public async Task<double?> GetAbuserScoreAsync(uint asn, CancellationToken ct = default)
        => (await GetAsnInfoAsync(asn, ct)).AbuserScore;
}
