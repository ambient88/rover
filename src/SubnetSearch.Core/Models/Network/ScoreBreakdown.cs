namespace SubnetSearch.Core.Models.Network;

public record ScoreBreakdown(
    double  Latency,     // 0–1
    double  Peering,     // 0–1
    double  Reputation,  // 0–1
    double  Size,        // 0–1
    double? Rpki         // 0–1, null if unavailable
);
