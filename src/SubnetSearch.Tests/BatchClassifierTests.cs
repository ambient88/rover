using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Tests;

public class BatchClassifierTests
{

    private sealed class SyncProgress<T> : IProgress<T>
    {
        public List<T> Items { get; } = new();
        public void Report(T value) { lock (Items) Items.Add(value); }
    }

    private sealed class StubIpClassifier : IIpClassifier
    {
        public int Calls;
        public Task<ClassificationResult> ClassifyAsync(string ip, CancellationToken ct = default)
        {
            Interlocked.Increment(ref Calls);
            bool hosting = ip.StartsWith("1.");
            return Task.FromResult(new ClassificationResult(hosting, 1, ip, "US", null, "stub"));
        }
    }

    private sealed class StubDomainClassifier : IDomainClassifier
    {
        public Task<DomainClassificationResult> ClassifyDomainAsync(string domain, CancellationToken ct = default)
            => Task.FromResult(new DomainClassificationResult(
                Domain: domain,
                IpResults: new[] { new ClassificationResult(domain.StartsWith("host"), 1, "o", "US", null, "s") },
                DomainRegistrar: null, DomainHostingProvider: null,
                ResolvedIpAddresses: Array.Empty<string>(), ReverseDns: null,
                RegistrationDate: null, ExpirationDate: null,
                NameServers: Array.Empty<string>(), WhoisStatus: null, DomainServiceType: null));
    }

    [Fact]
    public async Task ClassifyIps_PreservesOrder_AndReportsProgress()
    {
        var progress = new SyncProgress<BatchProgress>();
        var sut = new BatchClassifier(new StubIpClassifier(), new StubDomainClassifier());

        var results = await sut.ClassifyIpsAsync(
            new[] { "1.1.1.1", "2.2.2.2", "1.3.3.3" }, progress);

        results.Select(r => r.Organization).Should().Equal("1.1.1.1", "2.2.2.2", "1.3.3.3");
        results.Count(r => r.IsHosting).Should().Be(2);
        progress.Items.Should().NotBeEmpty();
    }

    [Fact]
    public async Task ClassifyIps_CachesByIp_NoDuplicateWork()
    {
        var ipc = new StubIpClassifier();
        var sut = new BatchClassifier(ipc, new StubDomainClassifier());

        await sut.ClassifyIpsAsync(new[] { "1.1.1.1", "1.1.1.1", "1.1.1.1" });

        ipc.Calls.Should().Be(1, "одинаковый IP классифицируется один раз (кэш)");
    }

    [Fact]
    public async Task ClassifyIps_EmptyInput_ReturnsEmpty()
        => (await new BatchClassifier(new StubIpClassifier(), new StubDomainClassifier())
                .ClassifyIpsAsync(Array.Empty<string>()))
            .Should().BeEmpty();

    [Fact]
    public async Task ClassifyDomains_ReportsHostingCount()
    {
        var progress = new SyncProgress<BatchProgress>();
        var sut = new BatchClassifier(new StubIpClassifier(), new StubDomainClassifier());

        var results = await sut.ClassifyDomainsAsync(
            new[] { "host-a.com", "plain-b.com" }, progress);

        results.Should().HaveCount(2);
        progress.Items.Should().HaveCount(2);
        progress.Items.Max(p => p.ProcessedItems).Should().Be(2);
        progress.Items.Max(p => p.HostingItems).Should().Be(1, "только host-a.* даёт hosting IP");
    }
}
