using FluentAssertions;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Офлайн-покрытие секций dedicatedOnly и cloudOnly (TAX-01, D-05):
//   - Default зеркалирует json: 49544 переехал nonHosting → dedicatedOnly; 11 гиперскейлеров
//     в cloudOnly.
//   - LoadAsync парсит новые секции теми же безопасными правилами (T-2.1-01/T-2.1-07):
//     битый/отсутствующий json → фолбэк Default без исключения.
//   - Pitfall 3: файл с ОДНОЙ лишь секцией dedicatedOnly/cloudOnly НЕ уходит в Default.
public class AsnExclusionsTests
{
    [Fact]
    public void Default_DedicatedOnly_ContainsI3D()
    {
        AsnExclusions.Default.DedicatedOnlyAsns.Should().Contain(49544u);
    }

    [Fact]
    public void Default_NonHosting_DoesNotContainI3D() // Pitfall 1/2 — синхронный перенос
    {
        AsnExclusions.Default.NonHostingAsns.Should().NotContain(49544u);
    }

    [Fact]
    public void Default_CloudOnly_ContainsAllThirteenHyperscalerAsns() // D-05 (+55990 Huawei Cloud China, +37963 Alibaba China)
    {
        AsnExclusions.Default.CloudOnlyAsns.Should().BeEquivalentTo(new uint[]
        {
            16509, 14618, 8075, 15169, 396982, 31898, 36351, 45102, 132203, 45090, 136907, 55990, 37963
        });
    }

    [Fact]
    public async Task LoadAsync_ParsesDedicatedOnlySection()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, """
            {
              "version": 1,
              "nonHosting": [ { "asn": 714, "org": "Apple" } ],
              "dedicatedOnly": [ { "asn": 12345, "org": "Test DC", "reason": "bare-metal only" } ]
            }
            """);
            var excl = await AsnExclusions.LoadAsync(path);
            excl.DedicatedOnlyAsns.Should().Contain(12345u);
            excl.NonHostingAsns.Should().Contain(714u);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadAsync_ParsesCloudOnlySection() // D-05
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, """
            {
              "version": 1,
              "nonHosting": [ { "asn": 714, "org": "Apple" } ],
              "cloudOnly": [ { "asn": 16509, "org": "AWS", "reason": "hyperscaler cloud" } ]
            }
            """);
            var excl = await AsnExclusions.LoadAsync(path);
            excl.CloudOnlyAsns.Should().Contain(16509u);
            excl.NonHostingAsns.Should().Contain(714u);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadAsync_OnlyDedicatedOnly_DoesNotFallBackToDefault() // Pitfall 3
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, """
            {
              "version": 1,
              "dedicatedOnly": [ { "asn": 12345, "org": "Test DC" } ]
            }
            """);
            var excl = await AsnExclusions.LoadAsync(path);
            excl.DedicatedOnlyAsns.Should().Contain(12345u);
            // Не Default: остальные секции пусты, а не унаследованы из зашитых дефолтов.
            excl.NonHostingAsns.Should().BeEmpty();
            excl.KnownCdnAsns.Should().BeEmpty();
            excl.KnownAiProviderAsns.Should().BeEmpty();
            excl.CloudOnlyAsns.Should().BeEmpty();
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadAsync_OnlyCloudOnly_DoesNotFallBackToDefault() // Pitfall 3, D-05
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, """
            {
              "version": 1,
              "cloudOnly": [ { "asn": 16509, "org": "AWS" } ]
            }
            """);
            var excl = await AsnExclusions.LoadAsync(path);
            excl.CloudOnlyAsns.Should().Contain(16509u);
            // Не Default: остальные секции пусты, а не унаследованы из зашитых дефолтов.
            excl.NonHostingAsns.Should().BeEmpty();
            excl.KnownCdnAsns.Should().BeEmpty();
            excl.KnownAiProviderAsns.Should().BeEmpty();
            excl.DedicatedOnlyAsns.Should().BeEmpty();
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadAsync_MissingFile_ReturnsDefault()
    {
        var excl = await AsnExclusions.LoadAsync(Path.Combine(Path.GetTempPath(), $"nope-{Guid.NewGuid():N}.json"));
        excl.Should().BeSameAs(AsnExclusions.Default);
    }

    [Fact]
    public async Task LoadAsync_CorruptJson_ReturnsDefaultWithoutThrowing() // T-2.1-01
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "{ this is not valid json ]]]");
            var excl = await AsnExclusions.LoadAsync(path);
            excl.Should().BeSameAs(AsnExclusions.Default);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadAsync_RepositoryDataFile_HasI3DMigrated() // проверка миграции данных
    {
        var repoFile = FindRepositoryDataFile();
        repoFile.Should().NotBeNull("data/asn-exclusions.json должен находиться при запуске из репозитория");

        var excl = await AsnExclusions.LoadAsync(repoFile!);
        excl.DedicatedOnlyAsns.Should().Contain(49544u, "i3D переехал в dedicatedOnly");
        excl.NonHostingAsns.Should().NotContain(49544u, "i3D удалён из nonHosting");
    }

    [Fact]
    public async Task LoadAsync_RepositoryDataFile_HasCloudOnlySection() // D-05
    {
        var repoFile = FindRepositoryDataFile();
        repoFile.Should().NotBeNull("data/asn-exclusions.json должен находиться при запуске из репозитория");

        var excl = await AsnExclusions.LoadAsync(repoFile!);
        excl.CloudOnlyAsns.Should().Contain(16509u, "AWS размечен в cloudOnly");
    }

    // Поиск data/asn-exclusions.json вверх по дереву от каталога сборки.
    private static string? FindRepositoryDataFile()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "data", "asn-exclusions.json");
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        return null;
    }
}
