namespace SubnetSearch.Core.Models.Classification;

public record ClassificationResult(
    bool IsHosting,
    uint? Asn,
    string? Organization,
    string? Country,
    string? Website,
    string Source,
    HostingType? HostingType = null,
    DateTime? RegistrationDate = null,
    DateTime? UpdatedDate = null,
    string? Status = null,
    // Шаг 1: базовая сетевая информация
    string? Ptr = null,
    string? IpRange = null,
    string? Rir = null,
    string? AbuseEmail = null,
    // Шаг 2: геолокация
    string? City = null,
    string? Region = null,
    double? Latitude = null,
    double? Longitude = null,
    string? Timezone = null,
    // Шаг 3: репутация (IPsum)
    int? ReputationScore = null,  // null = база не загружена, 0 = чистый, >0 = число источников
    // PeeringDB: пиринги и регионы
    int? PeeringCount = null,
    IReadOnlyList<string>? IxLocations = null,
    // HTTP/TLS fingerprint
    SubnetSearch.Core.Models.Network.HttpFingerprintResult? Http = null
);