using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IDomainClassifier : IDisposable
{
    Task<DomainClassificationResult> ClassifyDomainAsync(string domain, CancellationToken cancellationToken = default);
    void IDisposable.Dispose() { }
}
