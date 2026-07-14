using System.Text.Json;
using FluentAssertions;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

public class ProviderIndexCacheTests : IDisposable
{
    private readonly string _dir;
    public ProviderIndexCacheTests()
    {
        _dir = Directory.CreateTempSubdirectory().FullName;
    }
    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    private static IReadOnlyDictionary<string, IReadOnlyList<uint>> Map(
        params (string Cc, uint[] Asns)[] entries)
        => entries.ToDictionary(e => e.Cc, e => (IReadOnlyList<uint>)e.Asns);

    [Fact]
    public async Task Load_MissingFile_ReturnsNull()
        => (await new ProviderIndexCache(_dir).LoadAsync()).Should().BeNull();

    [Fact]
    public async Task Save_ThenLoad_RoundTrips()
    {
        var cache = new ProviderIndexCache(_dir);
        await cache.SaveAsync(Map(("FI", new uint[] { 1, 2 }), ("NL", new uint[] { 3 })));

        var loaded = await cache.LoadAsync();

        loaded.Should().NotBeNull();
        loaded!["FI"].Should().Equal(1u, 2u);
        loaded["NL"].Should().Equal(3u);
    }

    [Fact]
    public async Task Save_MergesWithoutDroppingOtherCountries()
    {
        var cache = new ProviderIndexCache(_dir);
        await cache.SaveAsync(Map(("FI", new uint[] { 1 })));
        await cache.SaveAsync(Map(("NL", new uint[] { 9 }))); // different country

        var loaded = await cache.LoadAsync();

        loaded!.Keys.Should().BeEquivalentTo(new[] { "FI", "NL" }, "merge preserves the earlier entry");
    }

    [Fact]
    public async Task Load_ExpiredEntry_IsFilteredOut()
    {
        // Hand-craft a cache file with a stale timestamp (older than the 7-day TTL).
        var stale = DateTime.UtcNow.AddDays(-8).ToString("o");
        var json = "{" + $"\"FI\":{{\"ts\":\"{stale}\",\"asns\":[1,2]}}" + "}";
        await File.WriteAllTextAsync(Path.Combine(_dir, "provider-index-cache.json"), json);

        (await new ProviderIndexCache(_dir).LoadAsync())
            .Should().BeNull("the only entry is expired → treated as a full miss");
    }

    [Fact]
    public async Task Load_CorruptFile_ReturnsNull()
    {
        await File.WriteAllTextAsync(Path.Combine(_dir, "provider-index-cache.json"), "{ broken");

        (await new ProviderIndexCache(_dir).LoadAsync()).Should().BeNull();
    }

    [Fact]
    public async Task Save_CorruptExistingFile_StartsFreshInsteadOfFailing()
    {
        await File.WriteAllTextAsync(Path.Combine(_dir, "provider-index-cache.json"), "{ broken");
        var cache = new ProviderIndexCache(_dir);

        await cache.SaveAsync(Map(("FI", new uint[] { 5 })));

        var loaded = await cache.LoadAsync();
        loaded.Should().NotBeNull("the unreadable old cache is replaced, not merged");
        loaded!["FI"].Should().Equal(5u);
    }

    [Fact]
    public async Task Save_UnwritableDirectory_IsBestEffortAndDoesNotThrow()
    {
        var cache = new ProviderIndexCache(Path.Combine(_dir, "missing-subdir"));

        var act = () => cache.SaveAsync(Map(("FI", new uint[] { 1 })));

        await act.Should().NotThrowAsync("the cache is an optimization, never a hard failure");
    }
}
