using System.IO.Compression;
using System.Text;
using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

public class CaidaClassificationLoaderTests : IDisposable
{
    private readonly string _dir;
    public CaidaClassificationLoaderTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"caida-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
    }
    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    private string WriteGz(string content)
    {
        string path = Path.Combine(_dir, "caida.txt.gz");
        using var fs = File.Create(path);
        using var gz = new GZipStream(fs, CompressionLevel.Fastest);
        gz.Write(Encoding.UTF8.GetBytes(content));
        return path;
    }

    [Fact]
    public async Task Load_ParsesAsnPipeClass_SkipsCommentsAndMalformed()
    {
        string path = WriteGz(
            "# CAIDA AS classification\n" +
            "13335|CAIDA|Content\n" +
            "\n" +
            "3356|CAIDA|Transit/Access\n" +
            "notanumber|CAIDA|Content\n" +   // Skip an invalid ASN.
            "64500|CAIDA\n" +                // Skip rows with too few columns.
            "64501|CAIDA|Enterprise\n");

        var map = await CaidaClassificationLoader.LoadAsync(path);

        map.Should().HaveCount(3);
        map[13335u].Should().Be("Content");
        map[3356u].Should().Be("Transit/Access");
        map[64501u].Should().Be("Enterprise");
        map.ContainsKey(64500u).Should().BeFalse("row with too few columns is skipped");
    }

    [Fact]
    public async Task Load_MissingFile_ReturnsEmpty()
        => (await CaidaClassificationLoader.LoadAsync(Path.Combine(_dir, "nope.gz")))
            .Should().BeEmpty();

    [Fact]
    public async Task Load_CorruptGzip_ReturnsEmptyWithoutThrowing()
    {
        string path = Path.Combine(_dir, "bad.txt.gz");
        File.WriteAllText(path, "this is not a gzip stream");

        (await CaidaClassificationLoader.LoadAsync(path)).Should().BeEmpty();
    }

    [Fact]
    public async Task Load_EmptyClass_SkipsEntry()
    {
        string path = WriteGz("64510|CAIDA|\n64511|CAIDA|Content\n");

        var map = await CaidaClassificationLoader.LoadAsync(path);

        map.Should().ContainSingle();
        map[64511u].Should().Be("Content");
    }
}
