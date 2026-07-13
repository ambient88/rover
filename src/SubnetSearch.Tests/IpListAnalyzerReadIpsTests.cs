using System.Net;
using FluentAssertions;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Covers the streaming ReadIpsAsync HTTP/file paths (distinct from ReadSourceAsync string variant).
public class IpListAnalyzerReadIpsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory().FullName;
    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    [Fact]
    public async Task ReadIps_Http_ExtractsAndDeduplicates()
    {
        using var http = new HttpClient(
            TestHttpMessageHandler.Always(HttpStatusCode.OK, "1.2.3.4 noise 5.6.7.8\nagain 1.2.3.4"));

        var ips = await IpListAnalyzer.ReadIpsAsync("https://example.com/list.txt", http);

        ips.Should().Equal("1.2.3.4", "5.6.7.8");
    }

    [Fact]
    public async Task ReadIps_LocalFile_ReadsIps()
    {
        string path = Path.Combine(_dir, "ips.txt");
        await File.WriteAllTextAsync(path, "10.0.0.1\n8.8.8.8\n");
        using var http = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.OK, ""));

        var ips = await IpListAnalyzer.ReadIpsAsync(path, http);

        ips.Should().Contain("8.8.8.8");
    }

    [Fact]
    public async Task ReadIps_DirectIpUrl_ThrowsSsrfGuard()
    {
        using var http = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.OK, ""));

        Func<Task> act = () => IpListAnalyzer.ReadIpsAsync("http://93.184.216.34/list", http);
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task ReadIps_DisallowedExtension_Throws()
    {
        string path = Path.Combine(_dir, "config.yaml");
        await File.WriteAllTextAsync(path, "8.8.8.8");
        using var http = new HttpClient(TestHttpMessageHandler.Always(HttpStatusCode.OK, ""));

        Func<Task> act = () => IpListAnalyzer.ReadIpsAsync(path, http);
        await act.Should().ThrowAsync<ArgumentException>();
    }
}
