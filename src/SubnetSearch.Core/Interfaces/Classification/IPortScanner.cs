namespace SubnetSearch.Core.Interfaces.Classification;

public interface IPortScanner
{
    Task<IReadOnlyList<int>> ScanAsync(string host, IEnumerable<int>? ports = null, CancellationToken cancellationToken = default);
}
