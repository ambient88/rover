using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Tests;

public sealed class DerivedHostingAsnCacheTests : IDisposable
{
    private readonly string _dataDir = Directory.CreateTempSubdirectory().FullName;

    private sealed class StubIndex(Func<uint, Ip2AsnRecord?> find) : IIpRangeIndex
    {
        public int Calls { get; private set; }

        public Ip2AsnRecord? Find(uint ipInt)
        {
            Calls++;
            return find(ipInt);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_dataDir))
            Directory.Delete(_dataDir, true);
    }

    [Fact]
    public void LoadOrBuild_BuildsCacheAndReusesIt()
    {
        HostingIpRange[] ranges =
        [
            new() { StartIp = 10, EndIp = 19, ProviderName = "One" },
            new() { StartIp = 20, EndIp = 29, ProviderName = "Missing" },
            new() { StartIp = 30, EndIp = 39, ProviderName = "Zero" }
        ];
        var firstIndex = new StubIndex(ip => ip switch
        {
            10 => Record(10, 64500),
            30 => Record(30, 0),
            _ => null
        });

        HashSet<uint> first = DerivedHostingAsnCache.LoadOrBuild(
            _dataDir, ranges, firstIndex);

        first.Should().BeEquivalentTo([64500u]);
        firstIndex.Calls.Should().Be(3);

        var cachedIndex = new StubIndex(_ => throw new InvalidOperationException(
            "The index must not be queried on a cache hit."));
        HashSet<uint> cached = DerivedHostingAsnCache.LoadOrBuild(
            _dataDir, ranges, cachedIndex);

        cached.Should().BeEquivalentTo([64500u]);
        cachedIndex.Calls.Should().Be(0);
    }

    [Fact]
    public void LoadOrBuild_InputStampChangeRebuildsCache()
    {
        HostingIpRange[] ranges =
        [
            new() { StartIp = 10, EndIp = 19, ProviderName = "Provider" }
        ];
        DerivedHostingAsnCache.LoadOrBuild(
            _dataDir, ranges, new StubIndex(_ => Record(10, 64500)));
        File.WriteAllText(Path.Combine(_dataDir, "ipcat-datacenters.csv"), "changed");
        var changedIndex = new StubIndex(_ => Record(10, 64501));

        HashSet<uint> changed = DerivedHostingAsnCache.LoadOrBuild(
            _dataDir, ranges, changedIndex);

        changed.Should().BeEquivalentTo([64501u]);
        changedIndex.Calls.Should().Be(1);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LoadOrBuild_InvalidCacheRebuilds(bool truncate)
    {
        HostingIpRange[] ranges =
        [
            new() { StartIp = 10, EndIp = 19, ProviderName = "Provider" }
        ];
        DerivedHostingAsnCache.LoadOrBuild(
            _dataDir, ranges, new StubIndex(_ => Record(10, 64500)));
        string cachePath = Path.Combine(
            DerivedCachePath.ForDataDirectory(_dataDir, "classification"),
            "hosting-asns-v1.bin");
        File.WriteAllBytes(
            cachePath,
            truncate ? [1, 2, 3] : BitConverter.GetBytes(123));
        var rebuiltIndex = new StubIndex(_ => Record(10, 64502));

        HashSet<uint> rebuilt = DerivedHostingAsnCache.LoadOrBuild(
            _dataDir, ranges, rebuiltIndex);

        rebuilt.Should().BeEquivalentTo([64502u]);
        rebuiltIndex.Calls.Should().Be(1);
    }

    [Fact]
    public void LoadOrBuild_UnwritableCachePath_StillReturnsBuiltResult()
    {
        HostingIpRange[] ranges =
        [
            new() { StartIp = 10, EndIp = 19, ProviderName = "Provider" }
        ];
        string cachePath = Path.Combine(
            DerivedCachePath.ForDataDirectory(_dataDir, "classification"),
            "hosting-asns-v1.bin");
        // A directory squatting on the cache file name makes the final File.Move fail,
        // exercising the best-effort write path (swallow + temp cleanup).
        Directory.CreateDirectory(cachePath);
        try
        {
            HashSet<uint> result = DerivedHostingAsnCache.LoadOrBuild(
                _dataDir, ranges, new StubIndex(_ => Record(10, 64500)));

            result.Should().BeEquivalentTo([64500u]);
            Directory.GetFiles(Path.GetDirectoryName(cachePath)!, "*.tmp")
                .Should().BeEmpty("the temp file is cleaned up after a failed move");
        }
        finally
        {
            Directory.Delete(cachePath);
        }
    }

    private static Ip2AsnRecord Record(uint ip, uint asn) => new()
    {
        StartIp = ip,
        EndIp = ip,
        Asn = asn,
        Country = "ZZ",
        Description = "Test"
    };
}
