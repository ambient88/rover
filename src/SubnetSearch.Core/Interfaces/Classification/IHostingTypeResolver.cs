using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IHostingTypeResolver
{
    Task<HostingType> ResolveAsync(
        string ipAddress,
        uint? asn,
        string? orgName,
        CancellationToken cancellationToken = default);

    Task<HostingType> ResolveWithPtrAsync(
        string ipAddress,
        uint? asn,
        string? orgName,
        string? ptr,
        CancellationToken cancellationToken = default)
        => ResolveAsync(ipAddress, asn, orgName, cancellationToken);
}
