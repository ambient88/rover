using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

public class InMemoryCacheExtraTests
{
    [Fact]
    public void GetOrAdd_Caches_Remove_And_Clear()
    {
        using var cache = new InMemoryCache(TimeSpan.FromMinutes(5));

        cache.GetOrAdd("k", () => "v").Should().Be("v");
        cache.GetOrAdd("k", () => "v2").Should().Be("v", "second call is served from cache");

        cache.Remove("k");
        cache.GetOrAdd("k", () => "v3").Should().Be("v3", "removed key is re-evaluated");

        cache.Clear();
        cache.GetOrAdd("k", () => "v4").Should().Be("v4", "cleared cache re-evaluates");
    }

    [Fact]
    public void GetOrAdd_ExpiredEntry_IsReevaluated()
    {
        using var cache = new InMemoryCache(TimeSpan.FromMilliseconds(-1)); // entries expire instantly

        cache.GetOrAdd("k", () => "a");
        cache.GetOrAdd("k", () => "b").Should().Be("b", "an expired entry is recomputed");
    }

    [Fact]
    public void GetOrAdd_PerCallTtl_Overrides_Default()
    {
        using var cache = new InMemoryCache(TimeSpan.FromMilliseconds(-1));

        // A positive per-call TTL keeps the entry alive despite the expired default.
        cache.GetOrAdd("k", () => "a", TimeSpan.FromMinutes(5));
        cache.GetOrAdd("k", () => "b", TimeSpan.FromMinutes(5)).Should().Be("a");
    }
}
