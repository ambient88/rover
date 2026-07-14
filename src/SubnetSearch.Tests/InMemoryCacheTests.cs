using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

// InMemoryCache runs a lazy factory once for a live key, recreates expired entries, and supports removal and clearing.
public class InMemoryCacheTests
{
    [Fact]
    public void GetOrAdd_CachesValue_FactoryCalledOnce()
    {
        using var cache = new InMemoryCache(TimeSpan.FromHours(1));
        int calls = 0;
        string Factory() { calls++; return "value"; }

        cache.GetOrAdd("k", Factory).Should().Be("value");
        cache.GetOrAdd("k", Factory).Should().Be("value");

        calls.Should().Be(1, "живой ключ не пересчитывается");
    }

    [Fact]
    public void GetOrAdd_DifferentKeys_IndependentValues()
    {
        using var cache = new InMemoryCache(TimeSpan.FromHours(1));

        cache.GetOrAdd("a", () => "A").Should().Be("A");
        cache.GetOrAdd("b", () => "B").Should().Be("B");
    }

    [Fact]
    public void GetOrAdd_ExpiredEntry_RecomputesValue()
    {
        using var cache = new InMemoryCache(TimeSpan.FromHours(1));
        int calls = 0;
        string Factory() { calls++; return $"v{calls}"; }

        cache.GetOrAdd("k", Factory, ttl: TimeSpan.Zero);
        Thread.Sleep(15); // Allow the entry to expire.
        var second = cache.GetOrAdd("k", Factory, ttl: TimeSpan.FromHours(1));

        calls.Should().Be(2);
        second.Should().Be("v2");
    }

    [Fact]
    public void Remove_ForcesRecompute()
    {
        using var cache = new InMemoryCache(TimeSpan.FromHours(1));
        int calls = 0;
        string Factory() { calls++; return "x"; }

        cache.GetOrAdd("k", Factory);
        cache.Remove("k");
        cache.GetOrAdd("k", Factory);

        calls.Should().Be(2);
    }

    [Fact]
    public void Clear_EmptiesCache()
    {
        using var cache = new InMemoryCache(TimeSpan.FromHours(1));
        int calls = 0;
        string Factory() { calls++; return "x"; }

        cache.GetOrAdd("k", Factory);
        cache.Clear();
        cache.GetOrAdd("k", Factory);

        calls.Should().Be(2);
    }

    [Fact]
    public void GetOrAdd_NullFactoryResult_IsCached()
    {
        using var cache = new InMemoryCache(TimeSpan.FromHours(1));
        int calls = 0;
        string? Factory() { calls++; return null; }

        cache.GetOrAdd<string?>("k", Factory).Should().BeNull();
        cache.GetOrAdd<string?>("k", Factory).Should().BeNull();

        calls.Should().Be(1, "закэшированный null не пересчитывается");
    }
}
