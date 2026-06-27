using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IProviderScanner
{
    /// <summary>
    /// Принимает ASN ("AS213520", "213520") или название организации ("Senko Digital").
    /// </summary>
    Task<ProviderScanResult?> ScanAsync(string query, CancellationToken cancellationToken = default);
}
