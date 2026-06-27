namespace SubnetSearch.Core.Models.Classification;

public record TracerouteHop(
    int    HopNumber,
    string? IpAddress,
    string? Hostname,
    double? LatencyMs
);
