using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

// Офлайн-покрытие LoadTagWithNamesAsync (TAX-01, D-06): парсинг asn → имя из vpsh.csv,
// нужен для vpsh-supplement (эталон PLAY2GO AS215439). Формат строки: "AS215439,PLAY2GO LTD" —
// ASN до первой запятой, имя — весь остаток (включая внутренние запятые). Мягкая деградация:
// отсутствующий/повреждённый файл → пустой словарь, LoadTagAsync на том же файле не ломается.
public class BgpToolsTagLoaderTests
{
    [Fact]
    public async Task LoadTagWithNamesAsync_ParsesAsnAndName()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "AS215439,PLAY2GO LTD");
            var map = await BgpToolsTagLoader.LoadTagWithNamesAsync(path);
            map.Should().ContainKey(215439u).WhoseValue.Should().Be("PLAY2GO LTD");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadTagWithNamesAsync_NameWithComma_KeepsWholeRemainder()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "AS1,Foo, Inc.");
            var map = await BgpToolsTagLoader.LoadTagWithNamesAsync(path);
            map.Should().ContainKey(1u).WhoseValue.Should().Be("Foo, Inc.");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadTagWithNamesAsync_LineWithoutComma_IsSkipped()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "AS215439");
            var map = await BgpToolsTagLoader.LoadTagWithNamesAsync(path);
            map.Should().BeEmpty();
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadTagWithNamesAsync_EmptyName_IsSkipped()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "AS2,");
            var map = await BgpToolsTagLoader.LoadTagWithNamesAsync(path);
            map.Should().BeEmpty();
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadTagWithNamesAsync_NoAsPrefix_StillParses()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "3,Bar");
            var map = await BgpToolsTagLoader.LoadTagWithNamesAsync(path);
            map.Should().ContainKey(3u).WhoseValue.Should().Be("Bar");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadTagWithNamesAsync_MissingFile_ReturnsEmptyDictionary()
    {
        var map = await BgpToolsTagLoader.LoadTagWithNamesAsync(
            Path.Combine(Path.GetTempPath(), $"nope-{Guid.NewGuid():N}.csv"));
        map.Should().BeEmpty();
    }

    [Fact]
    public async Task LoadTagWithNamesAsync_DuplicateAsn_FirstEntryWins()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "AS215439,PLAY2GO LTD\nAS215439,SOME OTHER NAME");
            var map = await BgpToolsTagLoader.LoadTagWithNamesAsync(path);
            map.Should().ContainKey(215439u).WhoseValue.Should().Be("PLAY2GO LTD");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task LoadTagAsync_SameFile_StillReturnsAsnSet() // регресс: LoadTagAsync не сломан
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "AS215439,PLAY2GO LTD\nAS1,Foo, Inc.");
            var set = await BgpToolsTagLoader.LoadTagAsync(path);
            set.Should().BeEquivalentTo(new uint[] { 215439, 1 });
        }
        finally { File.Delete(path); }
    }
}
