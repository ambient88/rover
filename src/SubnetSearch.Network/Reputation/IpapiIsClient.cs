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
    // NOTE: the legacy endpoint https://ipapi.is/json/?asn=… returns 502 permanently —
    // the current API lives at https://api.ipapi.is/?q=… (same for IP queries).
    public Task<AsnInfo> GetAsnInfoAsync(uint asn, CancellationToken ct = default)
        => FetchAsnInfoAsync($"https://api.ipapi.is/?q=AS{asn}", ct);

    // Gets ASN info including abuser_score by querying a specific IP address.
    public Task<AsnInfo> GetAsnInfoForIpAsync(string ip, CancellationToken ct = default)
        => FetchAsnInfoAsync($"https://api.ipapi.is/?q={ip}", ct);

    private async Task<AsnInfo> FetchAsnInfoAsync(string url, CancellationToken ct)
    {
        bool acquired = false;
        try
        {
            await _throttle.WaitAsync(ct);
            acquired = true;
            using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            reqCts.CancelAfter(TimeSpan.FromSeconds(8));
            var json = await http.GetStringAsync(url, reqCts.Token);
            return ParseAsnInfo(json);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return new AsnInfo(null, null); }
        finally { if (acquired) _throttle.Release(); }
    }

    // Response shapes of api.ipapi.is:
    //   ASN query (?q=AS123): ASN fields at the ROOT ("asn" is a plain number).
    //   IP query  (?q=1.2.3.4): ASN fields nested under an "asn" OBJECT.
    // abuser_score is usually a string like "0.0013 (Low)" — extract the numeric prefix.
    public static AsnInfo ParseAsnInfo(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        JsonElement asnEl;
        if (root.TryGetProperty("asn", out var asnProp) && asnProp.ValueKind == JsonValueKind.Object)
            asnEl = asnProp;   // IP query: nested object
        else if (asnProp.ValueKind is JsonValueKind.Number or JsonValueKind.String)
            asnEl = root;      // ASN query: fields live at the root
        else
            return new AsnInfo(null, null);

        double? abuserScore = null;
        if (asnEl.TryGetProperty("abuser_score", out var scoreEl))
        {
            if (scoreEl.ValueKind == JsonValueKind.Number)
                abuserScore = scoreEl.GetDouble();
            else if (scoreEl.ValueKind == JsonValueKind.String)
            {
                // "0.0013 (Low)" → take the leading numeric token.
                var s = scoreEl.GetString();
                var firstToken = s?.Split(' ', 2)[0];
                if (double.TryParse(firstToken,
                        System.Globalization.NumberStyles.Float,
                        System.Globalization.CultureInfo.InvariantCulture, out var parsed))
                    abuserScore = parsed;
            }
        }

        string? type = asnEl.TryGetProperty("type", out var typeEl) && typeEl.ValueKind == JsonValueKind.String
            ? typeEl.GetString()
            : null;

        return new AsnInfo(abuserScore, type);
    }
}
