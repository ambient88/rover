using FluentAssertions;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Покрытие механизма per-entry TTL в RipeStatCache (PERF-01, D-07):
//   - Set(key, data, ttl) round-trips данные через TryGet как для "вечного" TTL
//     (FromDays(3650)), так и для короткого положительного TTL.
//   - Независимое истечение: запись с уже истёкшим TTL не возвращается TryGet,
//     а "вечная" запись, поставленная в тот же момент, — возвращается.
//   - FlushIfDirtyAsync выселяет истёкшие записи с диска, но сохраняет живые
//     (проверяется через свежий экземпляр на том же каталоге).
public class RipeStatCacheTests
{
    [Fact]
    public void Set_WithLongTtl_RoundTripsViaTryGet()
    {
        var dir = Directory.CreateTempSubdirectory();
        try
        {
            var cache = new RipeStatCache(dir.FullName);
            // "Навсегда" для RPKI — большой явный per-entry TTL.
            cache.Set("rpki_1234", "0.95", TimeSpan.FromDays(3650));

            cache.TryGet("rpki_1234", out var data).Should().BeTrue();
            data.Should().Be("0.95");
        }
        finally { Directory.Delete(dir.FullName, true); }
    }

    [Fact]
    public void Set_WithShortPositiveTtl_RoundTripsViaTryGet()
    {
        var dir = Directory.CreateTempSubdirectory();
        try
        {
            var cache = new RipeStatCache(dir.FullName);
            // Короткий, но ещё не истёкший TTL — данные должны читаться.
            cache.Set("ping_192.0.2.1", "42ms", TimeSpan.FromMinutes(10));

            cache.TryGet("ping_192.0.2.1", out var data).Should().BeTrue();
            data.Should().Be("42ms");
        }
        finally { Directory.Delete(dir.FullName, true); }
    }

    [Fact]
    public void Set_ExpiredEntry_NotReturned_WhileForeverSurvives()
    {
        var dir = Directory.CreateTempSubdirectory();
        try
        {
            var cache = new RipeStatCache(dir.FullName);
            // Две записи в один и тот же момент: одна уже истекла, другая "вечная".
            cache.Set("expired", "stale", TimeSpan.FromSeconds(-1));
            cache.Set("forever", "fresh", TimeSpan.FromDays(3650));

            // Истёкшая не возвращается...
            cache.TryGet("expired", out var expiredData).Should().BeFalse();
            expiredData.Should().BeNull();
            // ...а "вечная", поставленная в тот же момент, — возвращается.
            cache.TryGet("forever", out var foreverData).Should().BeTrue();
            foreverData.Should().Be("fresh");
        }
        finally { Directory.Delete(dir.FullName, true); }
    }

    [Fact]
    public async Task FlushIfDirtyAsync_EvictsExpired_KeepsLive_AcrossReload()
    {
        var dir = Directory.CreateTempSubdirectory();
        try
        {
            // Первый экземпляр: одна "вечная" + одна уже истёкшая запись, затем flush.
            var cache = await RipeStatCache.LoadAsync(dir.FullName);
            cache.Set("forever", "fresh", TimeSpan.FromDays(3650));
            cache.Set("expired", "stale", TimeSpan.FromSeconds(-1));
            await cache.FlushIfDirtyAsync();

            // Свежий экземпляр на том же каталоге читает уже отфильтрованный файл.
            var reloaded = await RipeStatCache.LoadAsync(dir.FullName);
            reloaded.TryGet("forever", out var foreverData).Should().BeTrue();
            foreverData.Should().Be("fresh");
            reloaded.TryGet("expired", out var expiredData).Should().BeFalse();
            expiredData.Should().BeNull();
        }
        finally { Directory.Delete(dir.FullName, true); }
    }
}
