using SubnetSearch.Core.Interfaces;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Classification;

public class BatchClassifier : IBatchClassifier
{
    private readonly IIpClassifier _ipClassifier;
    private readonly IDomainClassifier _domainClassifier;
    private readonly ICache _cache;

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
        using var semaphore = new SemaphoreSlim(Concurrency);

        // The cancellationToken is only passed to semaphore.WaitAsync (slot acquisition).
        // ClassifyAsync itself receives CancellationToken.None so the cached Task remains
        // valid for future batch calls after the current one is cancelled.
        // Trade-off: in-flight network requests (WHOIS, DNS) continue briefly after Ctrl+C,
        // but their results are cached and prevent redundant work on retry.
        var tasks = ips.Select(async (ip, i) =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                var result = await _cache.GetOrAdd(
                    $"ip:{ip}",
                    () => _ipClassifier.ClassifyAsync(ip, CancellationToken.None))!;

                if (result.IsHosting) Interlocked.Increment(ref hostingCount);
                int p = Interlocked.Increment(ref processed);
                progress?.Report(new BatchProgress
                {
                    TotalItems = ips.Count,
                    ProcessedItems = p,
                    HostingItems = hostingCount
                });
                return result;
            }
            finally
            {
                semaphore.Release();
            }
        }).ToList();

        // Task.WhenAll preserves result order matching the input list order.
        return await Task.WhenAll(tasks);
    }

    public async Task<IReadOnlyList<DomainClassificationResult>> ClassifyDomainsAsync(
        IEnumerable<string> domains,
        IProgress<BatchProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var domainList = domains.ToList();
        int processed = 0;
        int hostingCount = 0;
        using var semaphore = new SemaphoreSlim(Concurrency);

        var tasks = domainList.Select(async domain =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                var result = await _cache.GetOrAdd(
                    $"domain:{domain}",
                    () => _domainClassifier.ClassifyDomainAsync(domain, CancellationToken.None))!;

                if (result.IpResults.Any(r => r.IsHosting)) Interlocked.Increment(ref hostingCount);
                int p = Interlocked.Increment(ref processed);
                progress?.Report(new BatchProgress
                {
                    TotalItems = domainList.Count,
                    ProcessedItems = p,
                    HostingItems = hostingCount
                });
                return result;
            }
            finally
            {
                semaphore.Release();
            }
        }).ToList();

        return await Task.WhenAll(tasks);
    }
}
