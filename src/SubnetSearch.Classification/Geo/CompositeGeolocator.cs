using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Classification;

// Chains multiple geolocators: tries each in order, stops when result is "good enough".
// A result is considered incomplete when city and coordinates are both missing.
public sealed class CompositeGeolocator(IGeolocator primary, IGeolocator fallback) : IGeolocator
{
    public GeoLocation? Locate(string ipAddress) => primary.Locate(ipAddress);

    public async Task<GeoLocation?> LocateAsync(string ipAddress, CancellationToken ct = default)
    {
        var result = await primary.LocateAsync(ipAddress, ct);
        if (IsComplete(result)) return result;

        var fb = await fallback.LocateAsync(ipAddress, ct);
        return Merge(result, fb);
    }

    // Complete means we have at least city or coordinates.
    private static bool IsComplete(GeoLocation? g)
        => g != null && (g.City != null || (g.Latitude != null && g.Longitude != null));

    // Prefer primary fields, fill gaps from fallback.
    private static GeoLocation? Merge(GeoLocation? primary, GeoLocation? fallback)
    {
        if (primary == null) return fallback;
        if (fallback == null) return primary;

        return new GeoLocation(
            City:      primary.City      ?? fallback.City,
            Region:    primary.Region    ?? fallback.Region,
            Latitude:  primary.Latitude  ?? fallback.Latitude,
            Longitude: primary.Longitude ?? fallback.Longitude,
            Timezone:  primary.Timezone  ?? fallback.Timezone,
            Country:   primary.Country   ?? fallback.Country
        );
    }

    public void Dispose()
    {
        primary.Dispose();
        fallback.Dispose();
    }
}
