using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IHostingTypeResolver
{
    Task<HostingType> ResolveAsync(
        string ipAddress,
        uint? asn,
        string? orgName,
        CancellationToken cancellationToken = default);
}
