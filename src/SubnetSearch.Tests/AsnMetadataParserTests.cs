using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

public class AsnMetadataParserTests
{
    private static async Task<string> WriteTempAsJson(string body)
    {
        var path = Path.Combine(Path.GetTempPath(), $"asjson-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, body);
        return path;
    }

    [Fact]
    public async Task LoadNetworkProfilesAsync_ExtractsRoleAndReach()
    {
        var path = await WriteTempAsJson("""
        [
          {"asn":31027,"metadata":{"category":"hosting","networkRole":"major_transit"},
           "stats":{"connectivity":{"reach":41729}}},
          {"asn":215439,"metadata":{"category":"business","networkRole":"access_provider"},
           "stats":{"connectivity":{"reach":3}}},
          {"asn":999,"metadata":{"category":"hosting","networkRole":null},"stats":null}
        ]
        """);
        try
        {
            var map = await new AsnMetadataParser().LoadNetworkProfilesAsync(path);
            map[31027].NetworkRole.Should().Be("major_transit");
            map[31027].Reach.Should().Be(41729);
            map[215439].NetworkRole.Should().Be("access_provider");
            map[999].NetworkRole.Should().BeNull();
            map[999].Reach.Should().Be(0, "no stats means reach=0");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadAllAsync_ExtractsHostingAsns_WebsiteByAsnAndOrg()
    {
        var path = await WriteTempAsJson("""
        [
          {"asn":24940,"website":"https://hetzner.com","organization":"Hetzner","metadata":{"category":"hosting"}},
          {"asn":15169,"website":"https://google.com","organization":"Google","metadata":{"category":"isp"}},
          {"asn":64500,"organization":"NoSite","metadata":{"category":"hosting"}}
        ]
        """);
        try
        {
            var (hostingAsns, byAsn, byOrg) = await new AsnMetadataParser().LoadAllAsync(path);

            hostingAsns.Should().BeEquivalentTo(new uint[] { 24940, 64500 });
            byAsn[24940u].Should().Be("https://hetzner.com");
            byOrg["Hetzner"].Should().Be("https://hetzner.com");
            byOrg["google"].Should().Be("https://google.com", "org lookup is case-insensitive");
            byAsn.ContainsKey(64500u).Should().BeFalse("entry without website is not indexed");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadCategoriesAsync_MissingFile_ReturnsEmpty()
        => (await new AsnMetadataParser().LoadCategoriesAsync(
                Path.Combine(Path.GetTempPath(), $"nope-{Guid.NewGuid():N}.json")))
            .Should().BeEmpty();

    [Fact]
    public async Task LoadCategoriesAsync_SecondLoad_ReadsFromCache()
    {
        var path = await WriteTempAsJson("""[{"asn":1,"metadata":{"category":"hosting"}},{"asn":2,"metadata":{"category":"isp"}}]""");
        var cacheDir = Path.Combine(Path.GetTempPath(), $"asmeta-{Guid.NewGuid():N}");
        try
        {
            var parser = new AsnMetadataParser(cacheDir);
            (await parser.LoadCategoriesAsync(path))[1].Should().Be("hosting");   // builds + writes cache
            var second = await parser.LoadCategoriesAsync(path);                  // reads cache
            second[1].Should().Be("hosting");
            second[2].Should().Be("isp");
        }
        finally { File.Delete(path); if (Directory.Exists(cacheDir)) Directory.Delete(cacheDir, true); }
    }

    [Fact]
    public async Task LoadNetworkProfilesAsync_WithCacheDir_RoundTrips()
    {
        var path = await WriteTempAsJson("""[{"asn":5,"metadata":{"networkRole":"transit"},"stats":{"connectivity":{"reach":42}}}]""");
        var cacheDir = Path.Combine(Path.GetTempPath(), $"asnp-{Guid.NewGuid():N}");
        try
        {
            var parser = new AsnMetadataParser(cacheDir);
            (await parser.LoadNetworkProfilesAsync(path))[5].Reach.Should().Be(42);
            (await parser.LoadNetworkProfilesAsync(path))[5].NetworkRole.Should().Be("transit");
        }
        finally { File.Delete(path); if (Directory.Exists(cacheDir)) Directory.Delete(cacheDir, true); }
    }

    [Fact]
    public async Task LoadCategoriesAsync_SourceChange_InvalidatesCache()
    {
        var path = await WriteTempAsJson("""[{"asn":1,"metadata":{"category":"hosting"}}]""");
        var cacheDir = Path.Combine(Path.GetTempPath(), $"asmeta-cache-{Guid.NewGuid():N}");
        try
        {
            var parser = new AsnMetadataParser(cacheDir);
            (await parser.LoadCategoriesAsync(path))[1].Should().Be("hosting");
            await File.WriteAllTextAsync(path, """[{"asn":1,"metadata":{"category":"business"}}]""");
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddSeconds(2));

            var categories = await parser.LoadCategoriesAsync(path);

            categories[1].Should().Be("business");
        }
        finally
        {
            File.Delete(path);
            if (Directory.Exists(cacheDir)) Directory.Delete(cacheDir, true);
        }
    }
}
