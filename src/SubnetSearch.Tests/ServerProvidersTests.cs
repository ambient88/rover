using FluentAssertions;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

public class ServerProvidersTests
{
    private static string Temp(string body)
    {
        var p = Path.Combine(Path.GetTempPath(), $"sp-{Guid.NewGuid():N}.json");
        File.WriteAllText(p, body);
        return p;
    }

    [Fact]
    public async Task IsInCore_MatchesByType()
    {
        var basePath = Temp("""
        {"providers":[
          {"asn":24940,"name":"Hetzner","types":["vps","dedicated"]},
          {"asn":16509,"name":"AWS","types":["cloud"]}
        ]}
        """);
        var sp = await ServerProviders.LoadAsync(basePath, basePath + ".missing");
        File.Delete(basePath);

        sp.IsInCore(24940, "vps").Should().BeTrue();
        sp.IsInCore(24940, "dedicated").Should().BeTrue();
        sp.IsInCore(24940, "cloud").Should().BeFalse();
        sp.IsInCore(16509, "cloud").Should().BeTrue();
        sp.IsInCore(16509, "vps").Should().BeFalse();
        sp.IsInCoreAny(24940).Should().BeTrue();
        sp.IsInCoreAny(777).Should().BeFalse();
    }

    [Fact]
    public async Task LocalOverride_AddsOverridesAndRemoves()
    {
        var basePath = Temp("""
        {"providers":[
          {"asn":1,"name":"Base-A","types":["vps"]},
          {"asn":2,"name":"Base-B","types":["cloud"]}
        ]}
        """);
        var localPath = Temp("""
        {"providers":[
          {"asn":2,"name":"Removed","types":[]},
          {"asn":3,"name":"Local-C","types":["dedicated"]}
        ]}
        """);
        var sp = await ServerProviders.LoadAsync(basePath, localPath);
        File.Delete(basePath); File.Delete(localPath);

        sp.IsInCore(1, "vps").Should().BeTrue("база не тронута");
        sp.IsInCoreAny(2).Should().BeFalse("пустой types в local удаляет запись базы");
        sp.IsInCore(3, "dedicated").Should().BeTrue("local-only добавлен");
    }

    [Fact]
    public async Task IsAllowed_OnlyCoreMembers() // pure allowlist: авто-гейт убран
    {
        var basePath = Temp("""{"providers":[{"asn":24940,"name":"Hetzner","types":["vps"]}]}""");
        var sp = await ServerProviders.LoadAsync(basePath, basePath + ".x");
        File.Delete(basePath);

        sp.IsAllowed(24940, "vps").Should().BeTrue("в ядре по типу");
        sp.IsAllowed(24940, "server").Should().BeTrue("server = любой тип ядра");
        sp.IsAllowed(24940, "cloud").Should().BeFalse("неверный тип");
        sp.IsAllowed(31027, "vps").Should().BeFalse("карьер не в ядре — не проходит");
        sp.IsAllowed(215439, "vps").Should().BeFalse("мелкий vpsh больше НЕ проходит автоматически");
    }

    [Fact]
    public async Task IsAllowed_And_IsInCore_AreCaseInsensitive() // WR-01: typeFilter приходит сырым
    {
        // Тип в файле — в верхнем регистре, запрос — в разном.
        var basePath = Temp("""{"providers":[{"asn":24940,"name":"Hetzner","types":["VPS"]}]}""");
        var sp = await ServerProviders.LoadAsync(basePath, basePath + ".x");
        File.Delete(basePath);

        sp.IsInCore(24940, "vps").Should().BeTrue("хранимый тип case-insensitive");
        sp.IsAllowed(24940, "VPS").Should().BeTrue("запрос верхним регистром");
        sp.IsAllowed(24940, "Server").Should().BeTrue("server-shortcut case-insensitive");
        sp.CoreAsnsForType("Server").Should().Contain(24940u);
        sp.CoreAsnsForType("VPS").Should().Contain(24940u);
    }

    [Fact]
    public async Task HostingAlias_FoldsToServer_InCoreAsnsAndIsAllowed() // W1: --type hosting == server
    {
        var basePath = Temp("""
        {"providers":[
          {"asn":24940,"name":"Hetzner","types":["vps","dedicated"]},
          {"asn":16509,"name":"AWS","types":["cloud"]}
        ]}
        """);
        var sp = await ServerProviders.LoadAsync(basePath, basePath + ".x");
        File.Delete(basePath);

        // hosting — документированный алиас server: любой тип ядра.
        sp.CoreAsnsForType("hosting").Should().BeEquivalentTo(new uint[] { 24940, 16509 });
        sp.CoreAsnsForType("HOSTING").Should().BeEquivalentTo(new uint[] { 24940, 16509 });
        sp.IsAllowed(24940, "hosting").Should().BeTrue();
        sp.IsAllowed(16509, "hosting").Should().BeTrue();
        sp.CoreEntriesForType("hosting").Select(e => e.Asn)
            .Should().BeEquivalentTo(new uint[] { 24940, 16509 });
    }

    [Fact]
    public async Task LocalOverride_ReplacesTypeSet_NotUnion() // MergeFile — полная замена записи
    {
        var basePath  = Temp("""{"providers":[{"asn":5,"name":"Base","types":["vps"]}]}""");
        var localPath = Temp("""{"providers":[{"asn":5,"name":"Local","types":["cloud"]}]}""");
        var sp = await ServerProviders.LoadAsync(basePath, localPath);
        File.Delete(basePath); File.Delete(localPath);

        sp.IsInCore(5, "cloud").Should().BeTrue("local переопределил тип");
        sp.IsInCore(5, "vps").Should().BeFalse("это замена, а не объединение");
    }
}
