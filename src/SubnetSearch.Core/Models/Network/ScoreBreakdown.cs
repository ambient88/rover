namespace SubnetSearch.Core.Models.Network;

public record ScoreBreakdown(
    double  Latency,     // Value from 0 to 1.
    double  Peering,     // Value from 0 to 1.
    double  Reputation,  // Value from 0 to 1.
    double  Size,        // Value from 0 to 1.
    double? Rpki         // Value from 0 to 1, or null when unavailable.
);
