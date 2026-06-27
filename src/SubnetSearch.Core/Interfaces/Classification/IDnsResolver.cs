using System.Net;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IDnsResolver
{
    Task<IReadOnlyList<IPAddress>> ResolveAllIpAsync(string domain, CancellationToken cancellationToken = default);
    Task<string?> ReverseDnsAsync(IPAddress ip, CancellationToken cancellationToken = default);
}
