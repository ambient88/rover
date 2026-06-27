using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface ITracerouteService
{
    Task<IReadOnlyList<TracerouteHop>> TraceAsync(string host, CancellationToken cancellationToken = default);
}
