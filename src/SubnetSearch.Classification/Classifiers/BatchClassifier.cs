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
        var results = new ClassificationResult[ips.Count];

        // Bounded worker model: Parallel.ForEachAsync keeps at most `Concurrency` operations in
        // flight and pulls items lazily from the source, so it never materializes one
        // Task/state-machine per input up front. A large CIDR would otherwise allocate up to
        // ~1M tasks and risk OutOfMemoryException (F4). The loop-level token stops scheduling new
        // work on cancel; ClassifyAsync still receives CancellationToken.None so the cached Task
        // stays valid for later batch calls (in-flight requests are cached, not wasted).
        await Parallel.ForEachAsync(
            Enumerable.Range(0, ips.Count),
            new ParallelOptions { MaxDegreeOfParallelism = Concurrency, CancellationToken = cancellationToken },
            async (i, _) =>
            {
                var ip = ips[i];
                var result = await _cache.GetOrAdd(
                    $"ip:{ip}",
                    () => _ipClassifier.ClassifyAsync(ip, CancellationToken.None))!;

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

        // Bounded worker model (see ClassifyIpsAsync) — no per-item Task materialization (F4).
        await Parallel.ForEachAsync(
            Enumerable.Range(0, domainList.Count),
            new ParallelOptions { MaxDegreeOfParallelism = Concurrency, CancellationToken = cancellationToken },
            async (i, _) =>
            {
                var domain = domainList[i];
                var result = await _cache.GetOrAdd(
                    $"domain:{domain}",
                    () => _domainClassifier.ClassifyDomainAsync(domain, CancellationToken.None))!;

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
}
