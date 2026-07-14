using FluentAssertions;
using SubnetSearch.Core.Interfaces.Data;
using SubnetSearch.Core.Models.Data;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

// DownloadManagerFactory creates the HTTP client, storage, and file list without network access.
public class DownloadManagerFactoryTests : IDisposable
{
    private readonly string _dir;
    public DownloadManagerFactoryTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"dmf-{Guid.NewGuid():N}");
    }
    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    [Fact]
    public void CreateHttpClient_DefaultTimeoutAndUserAgent()
    {
        using var client = DownloadManagerFactory.CreateHttpClient();

        client.Timeout.Should().Be(TimeSpan.FromSeconds(600));
        client.DefaultRequestHeaders.UserAgent.ToString().Should().Contain("SubnetSearch/1.0");
    }

    [Fact]
    public void CreateHttpClient_HonoursCustomTimeout()
    {
        using var client = DownloadManagerFactory.CreateHttpClient(new DownloadOptions { TimeoutSeconds = 30 });

        client.Timeout.Should().Be(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public void CreateHttpClient_WithProxy_DoesNotThrow()
    {
        using var client = DownloadManagerFactory.CreateHttpClient(
            new DownloadOptions { Proxy = "http://127.0.0.1:8080" });

        client.Should().NotBeNull();
    }

    [Fact]
    public void CreateStorage_ReturnsLocalStorage_AndCreatesDir()
    {
        var storage = DownloadManagerFactory.CreateStorage(_dir);

        storage.Should().BeOfType<LocalFileStorage>();
        Directory.Exists(_dir).Should().BeTrue();
    }

    [Fact]
    public void CreateDownloader_ReturnsFileDownloader()
    {
        using var http = new HttpClient();
        DownloadManagerFactory.CreateDownloader(http).Should().BeAssignableTo<IFileDownloader>();
    }

    [Fact]
    public void GetDefaultFiles_ContainsExpectedDescriptors()
    {
        var files = DownloadManagerFactory.GetDefaultFiles();
        var names = files.Select(f => f.FileName).ToList();

        names.Should().Contain(new[]
        {
            "ip2asn-v4.tsv.gz", "as.json", "ipcat-datacenters.csv",
            "cloud-provider-ip-addresses.json", "ipsum.txt", "dbip-city.mmdb.gz",
        });
        names.Should().Contain("bgptools-vpsh.csv", "теги bgp.tools добавляются в список");
        files.Should().OnlyContain(f => f.MinSize >= 0 && !string.IsNullOrEmpty(f.Url));
    }

    [Fact]
    public void GetDefaultFiles_DbIpUrl_IsMonthlyDated()
    {
        var dbip = DownloadManagerFactory.GetDefaultFiles().First(f => f.FileName == "dbip-city.mmdb.gz");

        dbip.Url.Should().MatchRegex(@"dbip-city-lite-\d{4}-\d{2}\.mmdb\.gz$");
    }

    [Fact]
    public void Create_BuildsDownloadManager()
    {
        using var http = new HttpClient();
        DownloadManagerFactory.Create(http, _dir).Should().NotBeNull();
    }
}
