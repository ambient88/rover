namespace SubnetSearch.Core.Models.Classification;

public record GeoLocation(
    string? City,
    string? Region,
    double? Latitude,
    double? Longitude,
    string? Timezone = null,
    string? Country = null
);
