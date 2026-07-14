using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

// Covers offline parsing of ASN and organization names from vpsh.csv for local supplements.
// The ASN appears before the first comma and the full remaining text becomes the name.
// A missing or malformed file returns an empty dictionary without breaking LoadTagAsync.
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
    public async Task LoadTagAsync_SameFile_StillReturnsAsnSet()
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

    [Fact]
    public async Task LoadTagAsync_SkipsBlankLines()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "AS7\n\n   \nAS8,Name");
            var set = await BgpToolsTagLoader.LoadTagAsync(path);
            set.Should().BeEquivalentTo(new uint[] { 7, 8 });
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void FileName_FollowsBgptoolsConvention()
        => BgpToolsTagLoader.FileName("vpsh").Should().Be("bgptools-vpsh.csv");

    [Fact]
    public async Task LoadAllAsync_ReturnsEntryPerTag_EmptyWhenFilesMissing()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"bgptags-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            // Missing tag files produce empty sets without throwing.
            await File.WriteAllTextAsync(Path.Combine(dir, "bgptools-vpsh.csv"), "AS215439,PLAY2GO");
            var all = await BgpToolsTagLoader.LoadAllAsync(dir);

            all.Keys.Should().BeEquivalentTo(BgpToolsTagLoader.Tags);
            all["vpsh"].Should().Contain(215439u);
            all["cdn"].Should().BeEmpty("файл тега отсутствует → пустое множество");
        }
        finally { Directory.Delete(dir, true); }
    }
}
