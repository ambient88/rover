using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using SubnetSearch.Network.Reputation;

namespace SubnetSearch.Tests;

public class SpamhausDropClientTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), $"spamhaus-{Guid.NewGuid():N}");

    private sealed class Handler(Func<HttpResponseMessage> response) : HttpMessageHandler
    {
        public int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(response());
        }
    }

    public SpamhausDropClientTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, true);
    }

    [Fact]
    public async Task Load_FreshDiskCacheAvoidsNetworkRequest()
    {
        var firstHandler = new Handler(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("AS64500 ; test\n", Encoding.UTF8)
        });
        using (var http = new HttpClient(firstHandler))
            await new SpamhausDropClient(http, _directory).LoadAsync();

        var secondHandler = new Handler(() => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        using var secondHttp = new HttpClient(secondHandler);
        var reloaded = new SpamhausDropClient(secondHttp, _directory);
        await reloaded.LoadAsync();

        reloaded.IsListed(64500).Should().BeTrue();
        secondHandler.Requests.Should().Be(0);
        File.Exists(Path.Combine(_directory, "spamhaus_cache.json")).Should().BeTrue();
        Directory.GetFiles(_directory, "*.tmp").Should().BeEmpty();
    }

    [Fact]
    public async Task Load_UsesStaleDiskCacheWhenRefreshFails()
    {
        string cachePath = Path.Combine(_directory, "spamhaus_cache.json");
        File.WriteAllText(cachePath, JsonSerializer.Serialize(new
        {
            FetchedAt = DateTimeOffset.UtcNow.AddDays(-2),
            Asns = new uint[] { 64501 }
        }));
        var handler = new Handler(() => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        using var http = new HttpClient(handler);
        var client = new SpamhausDropClient(http, _directory);

        await client.LoadAsync();

        handler.Requests.Should().Be(1);
        client.IsListed(64501).Should().BeTrue();
    }

    [Fact]
    public async Task Load_InvalidSuccessfulResponseKeepsStaleCache()
    {
        string cachePath = Path.Combine(_directory, "spamhaus_cache.json");
        File.WriteAllText(cachePath, JsonSerializer.Serialize(new
        {
            FetchedAt = DateTimeOffset.UtcNow.AddDays(-2),
            Asns = new uint[] { 64502 }
        }));
        var handler = new Handler(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("<html>blocked</html>")
        });
        using var http = new HttpClient(handler);
        var client = new SpamhausDropClient(http, _directory);

        await client.LoadAsync();

        client.IsListed(64502).Should().BeTrue();
        var persisted = JsonDocument.Parse(File.ReadAllText(cachePath));
        persisted.RootElement.GetProperty("Asns")[0].GetUInt32().Should().Be(64502);
    }
}
