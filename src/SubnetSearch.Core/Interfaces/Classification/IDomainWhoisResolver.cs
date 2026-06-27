using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IDomainWhoisResolver
{
    Task<DomainWhoisResult> ResolveAsync(string domain, CancellationToken cancellationToken = default);
}
