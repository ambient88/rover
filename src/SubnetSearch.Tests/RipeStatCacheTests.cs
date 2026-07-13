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

    // ── Негативное кэширование BGPView-фолбэка (gap closure Phase 10) ──
    // RipeStatClient.MarkEmpty/IsKnownEmpty: ASN, пустой и в RIPE Stat, и в BGPView,
    // помечается pfx0_{asn} и не дёргает троттлённый фолбэк в окне TTL.

    [Fact]
    public void MarkEmpty_IsKnownEmpty_RoundTrip()
    {
        var dir = Directory.CreateTempSubdirectory();
        try
        {
            var cache  = new RipeStatCache(dir.FullName);
            var client = new SubnetSearch.Network.RipeStatClient(new HttpClient(), cache);

            client.IsKnownEmpty(64512).Should().BeFalse("маркер ещё не ставился");
            client.MarkEmpty(64512);
            client.IsKnownEmpty(64512).Should().BeTrue("после MarkEmpty фолбэк пропускается");
            client.IsKnownEmpty(64513).Should().BeFalse("маркер индивидуален per-ASN");
        }
        finally { Directory.Delete(dir.FullName, true); }
    }

    [Fact]
    public void IsKnownEmpty_WithoutCache_AlwaysFalse()
    {
        // Без кэша (cache-less конструирование) фолбэк никогда не пропускается.
        var client = new SubnetSearch.Network.RipeStatClient(new HttpClient());
        client.MarkEmpty(64512); // no-op, не должен бросить
        client.IsKnownEmpty(64512).Should().BeFalse();
    }

    [Fact]
    public void MarkEmpty_ShortTtl_ExpiresIndependently()
    {
        // WR-01: неподтверждённая пустота (источник сбоил) — короткий маркер:
        // защищает троттленный BGPView от повторов в каждом прогоне, но не
        // замораживает здоровый ASN на сутки. Истёкший TTL → маркер невидим.
        var dir = Directory.CreateTempSubdirectory();
        try
        {
            var cache  = new RipeStatCache(dir.FullName);
            var client = new SubnetSearch.Network.RipeStatClient(new HttpClient(), cache);

            client.MarkEmpty(64512, TimeSpan.FromHours(1));
            client.IsKnownEmpty(64512).Should().BeTrue("часовой маркер активен");

            client.MarkEmpty(64513, TimeSpan.FromMilliseconds(-1)); // уже истёк
            client.IsKnownEmpty(64513).Should().BeFalse("истёкший маркер = отсутствие маркера");
        }
        finally { Directory.Delete(dir.FullName, true); }
    }

    [Fact]
    public void CachePrefixes_WritesUnderSamePfxKey()
    {
        var dir = Directory.CreateTempSubdirectory();
        try
        {
            var cache  = new RipeStatCache(dir.FullName);
            var client = new SubnetSearch.Network.RipeStatClient(new HttpClient(), cache);

            client.CachePrefixes(64512, ["192.0.2.0/24"], ["2001:db8::/32"]);
            // Результат фолбэка ложится под тот же pfx_-ключ, что и обычный RIPE-ответ.
            cache.TryGet("pfx_64512", out var data).Should().BeTrue();
            data.Should().Contain("192.0.2.0/24").And.Contain("2001:db8::/32");
        }
        finally { Directory.Delete(dir.FullName, true); }
    }

    // ── F6: RPKI result must not be cached for 10 years ──

    [Fact]
    public void RpkiAuthoritativeTtl_IsDaysNotYears()
        // RPKI/ROA state changes; an authoritative result should live days, not the former 3650.
        => SubnetSearch.Network.RipeStatClient.RpkiAuthoritativeTtl
            .Should().BeLessThanOrEqualTo(TimeSpan.FromDays(30));

    [Fact]
    public async Task Load_PreservesLegacyAndFreshRpkiEntries()
    {
        var dir = Directory.CreateTempSubdirectory();
        try
        {
            var legacy = DateTime.UtcNow.AddYears(10).ToString("o");   // old 3650-day entry
            var fresh  = DateTime.UtcNow.AddDays(3).ToString("o");     // new 7-day entry
            string json =
                "{" +
                $"\"rpki_1234\":{{\"e\":\"{legacy}\",\"d\":\"x\"}}," +
                $"\"rpki_5678\":{{\"e\":\"{fresh}\",\"d\":\"x\"}}," +
                $"\"pfx_1234\":{{\"e\":\"{legacy}\",\"d\":\"x\"}}" +
                "}";
            File.WriteAllText(Path.Combine(dir.FullName, "ripe_cache.json"), json);

            var cache = await RipeStatCache.LoadAsync(dir.FullName);

            cache.TryGet("rpki_1234", out _).Should().BeTrue("existing RPKI data must remain usable");
            cache.TryGet("rpki_5678", out _).Should().BeTrue("fresh short-TTL RPKI entry is kept");
            cache.TryGet("pfx_1234", out _).Should().BeTrue("other live cache entries are kept");
        }
        finally { Directory.Delete(dir.FullName, true); }
    }

    [Fact]
    public async Task GetRpkiValidityRatio_UsesExistingRpkiKey()
    {
        var dir = Directory.CreateTempSubdirectory();
        try
        {
            var cache = new RipeStatCache(dir.FullName);
            cache.Set("rpki_1234", "{\"r\":0.95}", TimeSpan.FromDays(3650));
            var client = new SubnetSearch.Network.RipeStatClient(new HttpClient(), cache);

            var ratio = await client.GetRpkiValidityRatioAsync(1234, Array.Empty<string>());

            ratio.Should().Be(0.95);
        }
        finally { Directory.Delete(dir.FullName, true); }
    }

    [Fact]
    public void RpkiCacheKey_RemainsStableWhenPrefixSetChanges()
    {
        string first = SubnetSearch.Network.RipeStatClient.BuildRpkiCacheKey(
            1234, ["10.0.0.0/24"]);
        string second = SubnetSearch.Network.RipeStatClient.BuildRpkiCacheKey(
            1234, ["10.0.1.0/24"]);

        first.Should().Be(second).And.Be("rpki_1234");
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
