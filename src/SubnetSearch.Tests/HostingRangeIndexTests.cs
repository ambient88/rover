using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Tests;

// HostingRangeIndex: агрегирует диапазоны дата-центров из трёх источников (ipcat CSV,
// rezmoss JSON, jhassine CSV) и ищет провайдера по IP бинарным поиском.
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
        // ipcat: startIp,endIp,"provider","website" (IP без кавычек, provider/website в кавычках)
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
        // jhassine: header + rows, cidr в col0, vendor в col3
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
    public async Task Load_NoFiles_EmptyIndex() // краевой случай: источников нет
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

    // Regression for F1: a wide range whose midpoint neighbour starts after the queried IP made
    // the old start-only binary search recurse left and miss the covering range entirely.
    // Layout (sorted by StartIp): Wide[.0-.200], Nested[.100-.150], Other[10.0.1.0-...].
    // Querying 10.0.0.175 lands on Nested (start .100), sees .175 > .150, jumps right to Other
    // (start 10.0.1.0 > .175), then null — even though Wide covers it.
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

    // When several ranges cover the IP, the most specific (latest-starting) one wins.
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

    // Boundary addresses (first and last of a range) must be covered even under overlap.
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
}
