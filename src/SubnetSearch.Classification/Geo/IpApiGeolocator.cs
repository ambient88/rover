using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using System.Text.Json;

namespace SubnetSearch.Classification;

// Fallback geolocator using ip-api.com (free, no key, city-level).
// Only called when the primary DB-IP source returns no city or coordinates.
public sealed class IpApiGeolocator : IGeolocator
{
    // Shared across all instances — lives for the process lifetime to avoid socket exhaustion.
    // ip-api.com free tier does not support HTTPS, so no TLS config needed.
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };

    // Synchronous path not supported — use LocateAsync.
    public GeoLocation? Locate(string ipAddress) => null;

    public async Task<GeoLocation?> LocateAsync(string ipAddress, CancellationToken ct = default)
    {
        try
        {
            var url = $"http://ip-api.com/json/{Uri.EscapeDataString(ipAddress)}" +
                      "?fields=status,city,regionName,countryCode,lat,lon,timezone";

            using var resp = await _http.GetAsync(url, ct);
            if (!resp.IsSuccessStatusCode) return null;

            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            var root = doc.RootElement;

            if (!root.TryGetProperty("status", out var st) || st.GetString() != "success")
                return null;

            string? city    = TryGetString(root, "city");
            string? region  = TryGetString(root, "regionName");
            string? country = TryGetString(root, "countryCode");
            string? tz      = TryGetString(root, "timezone");
            double? lat     = root.TryGetProperty("lat", out var latEl) ? latEl.GetDouble() : null;
            double? lon     = root.TryGetProperty("lon", out var lonEl) ? lonEl.GetDouble() : null;

            if (city == null && lat == null) return null;
            return new GeoLocation(city, region, lat, lon, tz, country);
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return null;
        }
    }

    private static string? TryGetString(JsonElement el, string key)
        => el.TryGetProperty(key, out var v) ? v.GetString() : null;

    // Dispose is a no-op: _http is static and lives for the process lifetime.
    public void Dispose() { }
}
