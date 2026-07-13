using FluentAssertions;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

public class LocalHostingAsnCacheTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), $"hosting-asn-cache-{Guid.NewGuid():N}");

    private sealed class StubIndex(Func<uint, Ip2AsnRecord?> find) : IIpRangeIndex
    {
        public int Calls { get; private set; }

        public Ip2AsnRecord? Find(uint ipInt)
        {
            Calls++;
            return find(ipInt);
        }
    }

    public LocalHostingAsnCacheTests()
    {
        Directory.CreateDirectory(_directory);
        WriteInputs("5.6.7.0,5.6.7.255,Example,example.com");
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, true);
    }

    [Fact]
    public async Task Get_FreshCacheSkipsRangeLookup()
    {
        var firstIndex = new StubIndex(_ => Record(64500));
        var cache = new LocalHostingAsnCache(_directory);
        var first = await cache.GetAsync(firstIndex);
        var secondIndex = new StubIndex(_ => throw new InvalidOperationException());

        var second = await new LocalHostingAsnCache(_directory).GetAsync(secondIndex);

        first.Should().Equal((64500u, 1));
        second.Should().Equal(first);
        firstIndex.Calls.Should().Be(1);
        secondIndex.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Get_InputFingerprintChangeRebuildsCache()
    {
        var cache = new LocalHostingAsnCache(_directory);
        await cache.GetAsync(new StubIndex(_ => Record(64500)));
        string inputPath = Path.Combine(_directory, "ipcat-datacenters.csv");
        File.WriteAllText(inputPath, "5.6.8.0,5.6.8.255,Example,example.com");
        File.SetLastWriteTimeUtc(inputPath, DateTime.UtcNow.AddSeconds(2));
        var changedIndex = new StubIndex(_ => Record(64501));

        var result = await cache.GetAsync(changedIndex);

        result.Should().Equal((64501u, 1));
        changedIndex.Calls.Should().Be(1);
    }

    [Fact]
    public async Task Get_CorruptCacheRebuildsResults()
    {
        var cache = new LocalHostingAsnCache(_directory);
        await cache.GetAsync(new StubIndex(_ => Record(64500)));
        File.WriteAllText(Path.Combine(_directory, "local_hosting_asns_cache.json"), "{broken");
        var rebuildingIndex = new StubIndex(_ => Record(64502));

        var result = await cache.GetAsync(rebuildingIndex);

        result.Should().Equal((64502u, 1));
        rebuildingIndex.Calls.Should().Be(1);
    }

    [Fact]
    public async Task Get_UsesFallbackCacheWhenPrimaryLocationIsNotWritable()
    {
        string primaryPath = Path.Combine(_directory, "local_hosting_asns_cache.json");
        Directory.CreateDirectory(primaryPath);
        string fallbackDirectory = DerivedCachePath.ForDataDirectory(_directory, "recommend");
        var firstIndex = new StubIndex(_ => Record(64503));

        try
        {
            var first = await new LocalHostingAsnCache(_directory).GetAsync(firstIndex);
            var secondIndex = new StubIndex(_ => throw new InvalidOperationException());
            var second = await new LocalHostingAsnCache(_directory).GetAsync(secondIndex);

            first.Should().Equal((64503u, 1));
            second.Should().Equal(first);
            secondIndex.Calls.Should().Be(0);
        }
        finally
        {
            if (Directory.Exists(fallbackDirectory))
                Directory.Delete(fallbackDirectory, true);
        }
    }

    private void WriteInputs(string ipcat)
    {
        File.WriteAllText(Path.Combine(_directory, "ipcat-datacenters.csv"), ipcat);
        File.WriteAllText(Path.Combine(_directory, "cloud-provider-ip-addresses.json"), "[]");
        File.WriteAllText(Path.Combine(_directory, "server-ip-addresses.csv"), "cidr,x,x,vendor");
        File.WriteAllText(Path.Combine(_directory, "ip2asn-v4.tsv.gz"), "fingerprint only");
    }

    private static Ip2AsnRecord Record(uint asn) => new()
    {
        StartIp = 0,
        EndIp = uint.MaxValue,
        Asn = asn,
        Country = "DE",
        Description = "Example"
    };
}
