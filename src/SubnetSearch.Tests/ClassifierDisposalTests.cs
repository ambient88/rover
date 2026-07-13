using SubnetSearch.Classification;
using SubnetSearch.Core.Interfaces;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Tests;

public class ClassifierDisposalTests
{
    [Fact]
    public void DomainClassifier_DisposesOwnedIpClassifierOnce()
    {
        var ip = new DisposableIpClassifier();
        var classifier = new DomainClassifier(
            ip, new StubDomainWhoisResolver(), new StubDnsResolver(),
            ownsIpClassifier: true);

        classifier.Dispose();
        classifier.Dispose();

        Assert.Equal(1, ip.DisposeCalls);
    }

    [Fact]
    public void BatchClassifier_DisposesOwnedGraphOnce()
    {
        var ip = new DisposableIpClassifier();
        var domain = new DisposableDomainClassifier();
        var cache = new DisposableCache();
        var classifier = new BatchClassifier(ip, domain, cache);

        classifier.Dispose();
        classifier.Dispose();

        Assert.Equal(1, ip.DisposeCalls);
        Assert.Equal(1, domain.DisposeCalls);
        Assert.Equal(1, cache.DisposeCalls);
    }

    private sealed class DisposableIpClassifier : IIpClassifier
    {
        public int DisposeCalls { get; private set; }

        public Task<ClassificationResult> ClassifyAsync(
            string ipAddress, CancellationToken cancellationToken = default)
            => Task.FromResult(new ClassificationResult(false, null, null, null, null, "stub"));

        public void Dispose() => DisposeCalls++;
    }

    private sealed class DisposableDomainClassifier : IDomainClassifier
    {
        public int DisposeCalls { get; private set; }

        public Task<DomainClassificationResult> ClassifyDomainAsync(
            string domain, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public void Dispose() => DisposeCalls++;
    }

    private sealed class DisposableCache : ICache, IDisposable
    {
        public int DisposeCalls { get; private set; }
        public T? GetOrAdd<T>(string key, Func<T> factory, TimeSpan? ttl = null) where T : class?
            => factory();
        public void Remove(string key) { }
        public void Clear() { }
        public void Dispose() => DisposeCalls++;
    }

    private sealed class StubDomainWhoisResolver : IDomainWhoisResolver
    {
        public Task<DomainWhoisResult> ResolveAsync(
            string domain, CancellationToken cancellationToken = default)
            => Task.FromResult(new DomainWhoisResult(
                null, null, null, null, null, null, null));
    }

    private sealed class StubDnsResolver : IDnsResolver
    {
        public Task<IReadOnlyList<System.Net.IPAddress>> ResolveAllIpAsync(
            string domain, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<System.Net.IPAddress>>([]);

        public Task<string?> ReverseDnsAsync(
            System.Net.IPAddress ip, CancellationToken cancellationToken = default)
            => Task.FromResult<string?>(null);
    }
}
