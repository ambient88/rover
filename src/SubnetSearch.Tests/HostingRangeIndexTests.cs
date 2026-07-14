using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Tests;

// HostingRangeIndex combines datacenter ranges from ipcat CSV, rezmoss JSON, and jhassine CSV,
// then finds a provider by IP through binary search.
public class HostingRangeIndexTests : IDisposable
{
    private readonly string _dir;

    public HostingRangeIndexTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"hri-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    private void Write(string name, string body) => File.WriteAllText(Path.Combine(_dir, name), body);

    [Fact]
    public async Task Load_ReadsIpcatCsv_AndFinds()
    {
        // ipcat stores unquoted IPs followed by quoted provider and website fields.
        Write("ipcat-datacenters.csv",
            "1.2.3.0,1.2.3.255,\"AcmeCloud\",\"acme.example\"\n");
        var index = new HostingRangeIndex();
        await index.LoadAsync(_dir);

        index.Count.Should().Be(1);
        var hit = index.Find(IpConverter.IpToUint("1.2.3.10"));
        hit.HasValue.Should().BeTrue();
        hit!.Value.ProviderName.Should().Be("AcmeCloud");
        hit.Value.Website.Should().Be("https://acme.example", "схема добавляется, если её нет");
    }

    [Fact]
    public async Task Load_IpcatQuotedComma_ParsesProviderAndWebsite()
    {
        Write("ipcat-datacenters.csv",
            "64.5.32.0,64.5.63.255,\"ThePlanet.com Internet Services, Inc.\",http://theplanet.com\n");
        var index = new HostingRangeIndex();
        await index.LoadAsync(_dir);

        var hit = index.Find(IpConverter.IpToUint("64.5.40.1"));
        hit.HasValue.Should().BeTrue();
        hit!.Value.ProviderName.Should().Be("ThePlanet.com Internet Services, Inc.");
        hit.Value.Website.Should().Be("http://theplanet.com", "website column is not corrupted by the comma");
    }

    [Fact]
    public async Task Load_ReadsRezmossJson()
    {
        Write("cloud-provider-ip-addresses.json",
            """[{"cidr":"5.6.7.0/24","provider":"JsonCloud","website":"https://json.example"}]""");
        var index = new HostingRangeIndex();
        await index.LoadAsync(_dir);

        index.Find(IpConverter.IpToUint("5.6.7.1"))!.Value.ProviderName.Should().Be("JsonCloud");
    }

    [Fact]
    public async Task Load_ReadsJhassineCsv_SkipsHeader()
    {
        // jhassine stores CIDR in column 0 and vendor in column 3 after a header row.
        Write("server-ip-addresses.csv",
            "cidr,region,service,vendor\n" +
            "\"9.9.9.0/24\",\"eu\",\"compute\",\"JhassineVendor\"\n");
        var index = new HostingRangeIndex();
        await index.LoadAsync(_dir);

        index.Find(IpConverter.IpToUint("9.9.9.9"))!.Value.ProviderName.Should().Be("JhassineVendor");
    }

    [Fact]
    public async Task Load_MergesAllSources()
    {
        Write("ipcat-datacenters.csv", "1.0.0.0,1.0.0.255,\"A\",\"a.example\"\n");
        Write("cloud-provider-ip-addresses.json", """[{"cidr":"2.0.0.0/24","provider":"B"}]""");
        Write("server-ip-addresses.csv", "cidr,x,y,vendor\n\"3.0.0.0/24\",\"\",\"\",\"C\"\n");
        var index = new HostingRangeIndex();
        await index.LoadAsync(_dir);

        index.Count.Should().Be(3);
    }

    [Fact]
    public async Task LoadRanges_ReadsRangesWithoutBuildingLookupSegments()
    {
        Write("ipcat-datacenters.csv", "1.0.0.0,1.0.0.255,\"A\",\"a.example\"\n");
        var index = new HostingRangeIndex();

        await index.LoadRangesAsync(_dir);

        index.Ranges.Should().ContainSingle();
        index.Find(IpConverter.IpToUint("1.0.0.1")).Should().BeNull();
    }

    [Fact]
    public async Task Load_NoFiles_EmptyIndex()
    {
        var index = new HostingRangeIndex();
        await index.LoadAsync(_dir);

        index.Count.Should().Be(0);
        index.Find(123u).Should().BeNull();
    }

    [Fact]
    public async Task Find_IpOutsideRanges_ReturnsNull()
    {
        Write("ipcat-datacenters.csv", "\"1.2.3.0\",\"1.2.3.255\",\"Acme\",\"acme.example\"\n");
        var index = new HostingRangeIndex();
        await index.LoadAsync(_dir);

        index.Find(IpConverter.IpToUint("8.8.8.8")).Should().BeNull();
    }

    [Fact]
    public async Task Load_CorruptIndexCache_RebuildsFromSource()
    {
        Write("ipcat-datacenters.csv", "10.0.0.0,10.0.0.255,\"H\",\"h.example\"\n");
        var cacheDir = Path.Combine(_dir, "cache");
        Directory.CreateDirectory(cacheDir);
        File.WriteAllText(Path.Combine(cacheDir, "hosting-index-v1.bin"), "not a valid binary cache");

        var index = new HostingRangeIndex(cacheDir);
        await index.LoadAsync(_dir); // A corrupt cache is rebuilt from CSV.

        index.Find(IpConverter.IpToUint("10.0.0.5"))!.Value.ProviderName.Should().Be("H");
    }

    [Fact]
    public async Task LoadRanges_ThenLoad_ReusesRangesCacheAndBuildsIndex()
    {
        Write("ipcat-datacenters.csv", "10.0.0.0,10.0.0.255,\"H\",\"h.example\"\n");
        var cacheDir = Path.Combine(_dir, "cache");

        var ranges = new HostingRangeIndex(cacheDir);
        await ranges.LoadRangesAsync(_dir); // ranges-only cache (no lookup segments)
        ranges.Count.Should().Be(1);

        var full = new HostingRangeIndex(cacheDir);
        await full.LoadAsync(_dir); // reuses ranges cache, builds the lookup index
        full.Find(IpConverter.IpToUint("10.0.0.5")).HasValue.Should().BeTrue();
    }

    [Fact]
    public async Task Find_OverlappingRanges_FindsCoveringWideRange()
    {
        Write("ipcat-datacenters.csv",
            "10.0.0.0,10.0.0.200,\"Wide\",\"wide.example\"\n" +
            "10.0.0.100,10.0.0.150,\"Nested\",\"nested.example\"\n" +
            "10.0.1.0,10.0.1.100,\"Other\",\"other.example\"\n");
        var index = new HostingRangeIndex();
        await index.LoadAsync(_dir);

        var hit = index.Find(IpConverter.IpToUint("10.0.0.175"));
        hit.HasValue.Should().BeTrue("the wide range covers this IP even though it is not at the search midpoint");
        hit!.Value.ProviderName.Should().Be("Wide");
    }

    [Fact]
    public async Task Find_NestedRanges_ReturnsMostSpecific()
    {
        Write("ipcat-datacenters.csv",
            "10.0.0.0,10.0.0.200,\"Wide\",\"wide.example\"\n" +
            "10.0.0.100,10.0.0.150,\"Nested\",\"nested.example\"\n" +
            "10.0.1.0,10.0.1.100,\"Other\",\"other.example\"\n");
        var index = new HostingRangeIndex();
        await index.LoadAsync(_dir);

        index.Find(IpConverter.IpToUint("10.0.0.120"))!.Value.ProviderName
            .Should().Be("Nested", "the narrower nested range is more specific than the wide one");
    }

    [Fact]
    public async Task Find_RangeBoundaries_AreCovered()
    {
        Write("ipcat-datacenters.csv",
            "10.0.0.0,10.0.0.200,\"Wide\",\"wide.example\"\n" +
            "10.0.0.100,10.0.0.150,\"Nested\",\"nested.example\"\n");
        var index = new HostingRangeIndex();
        await index.LoadAsync(_dir);

        index.Find(IpConverter.IpToUint("10.0.0.0")).HasValue.Should().BeTrue("start of Wide");
        index.Find(IpConverter.IpToUint("10.0.0.200")).HasValue.Should().BeTrue("end of Wide");
        index.Find(IpConverter.IpToUint("10.0.0.201")).Should().BeNull("just past the end");
    }

    [Fact]
    public async Task Find_RangeEndingAtMaximumAddress_IsCovered()
    {
        Write("ipcat-datacenters.csv",
            "255.255.255.0,255.255.255.255,\"LastRange\",\"last.example\"\n");
        var index = new HostingRangeIndex();
        await index.LoadAsync(_dir);

        index.Find(uint.MaxValue)!.Value.ProviderName.Should().Be("LastRange");
    }

    [Fact]
    public async Task Load_SourceChange_InvalidatesCache()
    {
        var cacheDir = Path.Combine(_dir, "cache");
        string sourcePath = Path.Combine(_dir, "ipcat-datacenters.csv");
        Write("ipcat-datacenters.csv", "1.0.0.0,1.0.0.255,First,first.example\n");
        var first = new HostingRangeIndex(cacheDir);
        await first.LoadAsync(_dir);

        Write("ipcat-datacenters.csv", "1.0.0.0,1.0.0.255,Other,other.example\n");
        File.SetLastWriteTimeUtc(sourcePath, DateTime.UtcNow.AddSeconds(2));
        var second = new HostingRangeIndex(cacheDir);
        await second.LoadAsync(_dir);

        second.Find(IpConverter.IpToUint("1.0.0.1"))!.Value.ProviderName.Should().Be("Other");
    }
}
