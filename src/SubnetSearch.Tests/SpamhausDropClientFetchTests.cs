using System.Net;
using FluentAssertions;
using SubnetSearch.Network.Reputation;

namespace SubnetSearch.Tests;

public class SpamhausDropClientFetchTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory().FullName;
    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    [Fact]
    public async Task Load_FetchesAndParsesDropList_ThenIsListed()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK,
            "; Spamhaus ASN-DROP\nAS64500 ; Bad Network\nAS64501\n; trailing comment\n");
        var client = new SpamhausDropClient(new HttpClient(handler), _dir);

        await client.LoadAsync();

        client.IsListed(64500).Should().BeTrue();
        client.IsListed(64501).Should().BeTrue();
        client.IsListed(99999).Should().BeFalse();
    }

    [Fact]
    public async Task Load_EmptyList_KeepsEmptySetWithoutThrowing()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "; only comments\n");
        var client = new SpamhausDropClient(new HttpClient(handler), _dir);

        await client.LoadAsync(); // InvalidDataException leaves the set empty when parsing yields no entries.

        client.IsListed(64500).Should().BeFalse();
    }

    [Fact]
    public async Task Load_SecondCallWithinTtl_SkipsNetwork()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "AS64500\n");
        var client = new SpamhausDropClient(new HttpClient(handler), _dir);

        await client.LoadAsync();
        await client.LoadAsync();

        handler.Requests.Should().HaveCount(1, "the in-memory copy is fresh for 24 hours");
    }

    [Fact]
    public async Task Load_ConcurrentCalls_SecondReusesFirstResult()
    {
        using var firstArrived = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        int requests = 0;
        var handler = TestHttpMessageHandler.Custom(_ =>
        {
            Interlocked.Increment(ref requests);
            firstArrived.Set();
            release.Wait(TimeSpan.FromSeconds(5));
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("AS64500\n"),
            };
        });
        var client = new SpamhausDropClient(new HttpClient(handler), _dir);

        // The stub handler blocks synchronously, so the first call needs its own thread.
        var first = Task.Run(() => client.LoadAsync());
        firstArrived.Wait(TimeSpan.FromSeconds(5)).Should().BeTrue();
        var second = Task.Run(() => client.LoadAsync()); // queues on the lock behind the first call
        // Let the second caller reach the lock, then release the response quickly:
        // the client's own request budget is 2 seconds and must not expire here.
        await Task.Delay(200);
        release.Set();
        await Task.WhenAll(first, second);

        requests.Should().Be(1, "the second caller sees fresh data after acquiring the lock");
        client.IsListed(64500).Should().BeTrue();
    }

    [Fact]
    public async Task Load_CancelledMidRequest_Rethrows()
    {
        using var cts = new CancellationTokenSource();
        var handler = TestHttpMessageHandler.Custom(_ =>
        {
            cts.Cancel();
            throw new OperationCanceledException(cts.Token);
        });
        var client = new SpamhausDropClient(new HttpClient(handler), _dir);

        var act = () => client.LoadAsync(cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task Load_DiskCacheWithEmptyAsnList_IsIgnored()
    {
        await File.WriteAllTextAsync(Path.Combine(_dir, "spamhaus_cache.json"),
            $$"""{"FetchedAt":"{{DateTimeOffset.UtcNow:O}}","Asns":[]}""");
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "AS64500\n");
        var client = new SpamhausDropClient(new HttpClient(handler), _dir);

        await client.LoadAsync();

        handler.Requests.Should().HaveCount(1, "an empty cached list carries no information");
        client.IsListed(64500).Should().BeTrue();
    }

    [Fact]
    public async Task Load_CorruptDiskCache_FallsBackToNetwork()
    {
        await File.WriteAllTextAsync(Path.Combine(_dir, "spamhaus_cache.json"), "{ broken");
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "AS64500\n");
        var client = new SpamhausDropClient(new HttpClient(handler), _dir);

        await client.LoadAsync();

        client.IsListed(64500).Should().BeTrue();
    }

    [Fact]
    public async Task Load_PrimaryCacheUnwritable_FallsBackToDerivedCacheDir()
    {
        // A directory squatting on the cache file name makes the primary write fail.
        Directory.CreateDirectory(Path.Combine(_dir, "spamhaus_cache.json"));
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "AS64500\n");
        var client = new SpamhausDropClient(new HttpClient(handler), _dir);

        await client.LoadAsync();

        client.IsListed(64500).Should().BeTrue();
        Directory.GetFiles(_dir, "*.tmp")
            .Should().BeEmpty("the temp file is cleaned up after a failed move");
    }
}
