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
    // Step 1: basic network information
    string? Ptr = null,
    string? IpRange = null,
    string? Rir = null,
    string? AbuseEmail = null,
    // Step 2: geolocation
    string? City = null,
    string? Region = null,
    double? Latitude = null,
    double? Longitude = null,
    string? Timezone = null,
    // Step 3: reputation (IPsum)
    int? ReputationScore = null,  // null = database not loaded, 0 = clean, >0 = number of sources
    // PeeringDB: peerings and regions
    int? PeeringCount = null,
    IReadOnlyList<string>? IxLocations = null,
    // HTTP/TLS fingerprint
    SubnetSearch.Core.Models.Network.HttpFingerprintResult? Http = null
);