using FluentAssertions;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Interfaces.Data;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Models.Data;

namespace SubnetSearch.Tests;

// Default interface members are real executable code; these tests pin their
// delegation behaviour using minimal stubs that implement only the abstract parts.
public class CoreInterfaceDefaultsTests
{
    private sealed class RecordingDownloader : IFileDownloader
    {
        public string? Url;
        public IProgress<DownloadProgress>? Progress;

        public Task<Stream> DownloadAsync(
            string url,
            DownloadOptions options,
            IProgress<DownloadProgress>? progress = null,
            CancellationToken cancellationToken = default,
            string? partialFilePath = null)
        {
            Url = url;
            Progress = progress;
            return Task.FromResult(Stream.Null);
        }

        public Task<ConditionalDownloadResult> ConditionalDownloadAsync(
            string url,
            string? etag,
            string? lastModified,
            DownloadOptions options,
            IProgress<DownloadProgress>? progress = null,
            CancellationToken cancellationToken = default,
            string? partialFilePath = null)
            => Task.FromResult(new ConditionalDownloadResult(true, null, null, null));
    }

    [Fact]
    public async Task Downloader_UrlOnlyOverload_DelegatesToCore()
    {
        var stub = new RecordingDownloader();

        await ((IFileDownloader)stub).DownloadAsync("http://x/file");

        stub.Url.Should().Be("http://x/file");
        stub.Progress.Should().BeNull();
    }

    [Fact]
    public async Task Downloader_DownloadProgressOverload_PassesProgressThrough()
    {
        var stub = new RecordingDownloader();
        var progress = new Progress<DownloadProgress>(_ => { });

        await ((IFileDownloader)stub).DownloadAsync("http://x/file", progress);

        stub.Progress.Should().BeSameAs(progress);
    }

    [Fact]
    public async Task Downloader_LongProgressOverload_WrapsAndForwardsByteCount()
    {
        var stub = new RecordingDownloader();
        long reported = 0;
        using var signal = new ManualResetEventSlim();
        var longProgress = new InlineProgress<long>(v => { reported = v; signal.Set(); });

        await ((IFileDownloader)stub).DownloadAsync("http://x/file", longProgress);

        stub.Progress.Should().NotBeNull("the default overload wraps IProgress<long>");
        stub.Progress!.Report(new DownloadProgress { BytesDownloaded = 42, TotalBytes = 100 });
        signal.Wait(TimeSpan.FromSeconds(5)).Should().BeTrue();
        reported.Should().Be(42);
    }

    [Fact]
    public async Task Downloader_NullLongProgress_PassesNullThrough()
    {
        var stub = new RecordingDownloader();

        await ((IFileDownloader)stub).DownloadAsync("http://x/file", (IProgress<long>?)null);

        stub.Progress.Should().BeNull();
    }

    // Synchronous IProgress<T>: Progress<T> posts to a sync context, so the wrapped
    // callback lands here on a pool thread; the event keeps the test deterministic.
    private sealed class InlineProgress<T> : IProgress<T>
    {
        private readonly Action<T> _handler;
        public InlineProgress(Action<T> handler) => _handler = handler;
        public void Report(T value) => _handler(value);
    }

    private sealed class MinimalBatchClassifier : IBatchClassifier
    {
        public Task<IReadOnlyList<ClassificationResult>> ClassifyIpsAsync(
            IEnumerable<string> ipAddresses,
            IProgress<BatchProgress>? progress = null,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<IReadOnlyList<DomainClassificationResult>> ClassifyDomainsAsync(
            IEnumerable<string> domains,
            IProgress<BatchProgress>? progress = null,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class MinimalDomainClassifier : IDomainClassifier
    {
        public Task<DomainClassificationResult> ClassifyDomainAsync(
            string domain, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class MinimalIpClassifier : IIpClassifier
    {
        public Task<ClassificationResult> ClassifyAsync(
            string ipAddress, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    [Fact]
    public void DefaultDispose_IsANoOpForAllClassifierInterfaces()
    {
        // Implementations without unmanaged state may skip Dispose entirely;
        // the interface defaults must not throw.
        var batch = (IDisposable)new MinimalBatchClassifier();
        var domain = (IDisposable)new MinimalDomainClassifier();
        var ip = (IDisposable)new MinimalIpClassifier();

        var act = () => { batch.Dispose(); domain.Dispose(); ip.Dispose(); };
        act.Should().NotThrow();
    }

    private sealed class FixedGeolocator : IGeolocator
    {
        public GeoLocation? Result;
        public GeoLocation? Locate(string ipAddress) => Result;
        public void Dispose() { }
    }

    [Fact]
    public async Task Geolocator_DefaultLocateAsync_DelegatesToSyncLocate()
    {
        var geo = new FixedGeolocator();

        (await ((IGeolocator)geo).LocateAsync("8.8.8.8")).Should().BeNull();

        geo.Result = new GeoLocation("Dallas", "TX", null, null, Country: "US");
        var located = await ((IGeolocator)geo).LocateAsync("8.8.8.8");
        located.Should().NotBeNull();
        located!.Country.Should().Be("US");
    }
}
