using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IPingService
{
    Task<PingStats?> PingAsync(string host, int count = 4, CancellationToken cancellationToken = default);
}
