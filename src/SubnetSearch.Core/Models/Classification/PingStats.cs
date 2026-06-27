namespace SubnetSearch.Core.Models.Classification;

public record PingStats(
    double MinMs,
    double AvgMs,
    double MaxMs,
    int PacketLoss,  // процент потерь 0-100
    bool IsTcp = false
);
