using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IProviderScanner
{
    /// <summary>
    /// Accepts an ASN ("AS213520", "213520") or an organization name ("Senko Digital").
    /// </summary>
    Task<ProviderScanResult?> ScanAsync(string query, CancellationToken cancellationToken = default);
}
