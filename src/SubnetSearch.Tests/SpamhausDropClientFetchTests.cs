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

        await client.LoadAsync(); // parse yields 0 → InvalidDataException is swallowed, set stays empty

        client.IsListed(64500).Should().BeFalse();
    }
}
