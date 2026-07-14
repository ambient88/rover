namespace SubnetSearch.Core.Models.Classification;

public record PingStats(
    double MinMs,
    double AvgMs,
    double MaxMs,
    int PacketLoss  // packet loss percentage 0-100
);
