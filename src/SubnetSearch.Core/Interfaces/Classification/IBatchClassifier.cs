using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IBatchClassifier : IDisposable
{
    Task<IReadOnlyList<ClassificationResult>> ClassifyIpsAsync(
        IEnumerable<string> ipAddresses,
        IProgress<BatchProgress>? progress = null,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<DomainClassificationResult>> ClassifyDomainsAsync(
        IEnumerable<string> domains,
        IProgress<BatchProgress>? progress = null,
        CancellationToken cancellationToken = default);

    void IDisposable.Dispose() { }
}
