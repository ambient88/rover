using SubnetSearch.Core.Interfaces;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Classification;

public class BatchClassifier : IBatchClassifier
{
    private readonly IIpClassifier _ipClassifier;
    private readonly IDomainClassifier _domainClassifier;
    private readonly ICache _cache;
    private int _disposed;

    // Concurrency limit: 8 simultaneous requests (WHOIS, DNS, API).
    private const int Concurrency = 8;

    public BatchClassifier(IIpClassifier ipClassifier, IDomainClassifier domainClassifier, ICache? cache = null)
    {
        _ipClassifier = ipClassifier;
        _domainClassifier = domainClassifier;
        _cache = cache ?? new InMemoryCache();
    }

    public async Task<IReadOnlyList<ClassificationResult>> ClassifyIpsAsync(
        IEnumerable<string> ipAddresses,
        IProgress<BatchProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var ips = ipAddresses.ToList();
        int processed = 0;
        int hostingCount = 0;
        var results = new ClassificationResult[ips.Count];

        // A cached operation remains reusable when one caller cancels its wait.
        await Parallel.ForEachAsync(
            Enumerable.Range(0, ips.Count),
            new ParallelOptions { MaxDegreeOfParallelism = Concurrency, CancellationToken = cancellationToken },
            async (i, loopCancellationToken) =>
            {
                var ip = ips[i];
                var task = _cache.GetOrAdd(
                    $"ip:{ip}",
                    () => _ipClassifier.ClassifyAsync(ip, CancellationToken.None))!;
                var result = await task.WaitAsync(loopCancellationToken);

                // Write by index to preserve input order in the result list.
                results[i] = result;
                if (result.IsHosting) Interlocked.Increment(ref hostingCount);
                int p = Interlocked.Increment(ref processed);
                progress?.Report(new BatchProgress
                {
                    TotalItems = ips.Count,
                    ProcessedItems = p,
                    HostingItems = hostingCount
                });
            });

        return results;
    }

    public async Task<IReadOnlyList<DomainClassificationResult>> ClassifyDomainsAsync(
        IEnumerable<string> domains,
        IProgress<BatchProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var domainList = domains.ToList();
        int processed = 0;
        int hostingCount = 0;
        var results = new DomainClassificationResult[domainList.Count];

        await Parallel.ForEachAsync(
            Enumerable.Range(0, domainList.Count),
            new ParallelOptions { MaxDegreeOfParallelism = Concurrency, CancellationToken = cancellationToken },
            async (i, loopCancellationToken) =>
            {
                var domain = domainList[i];
                var task = _cache.GetOrAdd(
                    $"domain:{domain}",
                    () => _domainClassifier.ClassifyDomainAsync(domain, CancellationToken.None))!;
                var result = await task.WaitAsync(loopCancellationToken);

                results[i] = result;
                if (result.IpResults.Any(r => r.IsHosting)) Interlocked.Increment(ref hostingCount);
                int p = Interlocked.Increment(ref processed);
                progress?.Report(new BatchProgress
                {
                    TotalItems = domainList.Count,
                    ProcessedItems = p,
                    HostingItems = hostingCount
                });
            });

        return results;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { _domainClassifier.Dispose(); }
        finally
        {
            try { _ipClassifier.Dispose(); }
            finally
            {
                if (_cache is IDisposable disposableCache) disposableCache.Dispose();
            }
        }
    }
}
