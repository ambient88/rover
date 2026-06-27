using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IDomainClassifier
{
    Task<DomainClassificationResult> ClassifyDomainAsync(string domain, CancellationToken cancellationToken = default);
}
