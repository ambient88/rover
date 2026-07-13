using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IIpClassifier : IDisposable
{
    Task<ClassificationResult> ClassifyAsync(string ipAddress, CancellationToken cancellationToken = default);
    void IDisposable.Dispose() { }
}
