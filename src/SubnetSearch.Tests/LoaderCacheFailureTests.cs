using System.IO.Compression;
using System.Text;
using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

// The three file loaders share the same derived-cache pattern: TryReadCache falls back
// to a rebuild on a corrupt cache, and TryWriteCache is best-effort (swallow + temp
// cleanup). These tests force both failure paths for each loader.
public sealed class LoaderCacheFailureTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory().FullName;
    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    private string SourceFile(string name, byte[] content)
    {
        string path = Path.Combine(_dir, name);
        File.WriteAllBytes(path, content);
        return path;
    }

    private string CacheDir()
    {
        string dir = Path.Combine(_dir, "cache");
        Directory.CreateDirectory(dir);
        return dir;
    }

    // A directory squatting on the cache file name makes File.Move fail after the
    // temp file is fully written, hitting the swallow branch and the temp cleanup.
    private static void BlockCacheFile(string cacheDir, string cacheFileName)
        => Directory.CreateDirectory(Path.Combine(cacheDir, cacheFileName));

    private static void AssertNoTempLeft(string cacheDir)
        => Directory.GetFiles(cacheDir, "*.tmp")
            .Should().BeEmpty("the temp file is cleaned up after a failed move");

    private static byte[] Gzip(string text)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true))
            gz.Write(Encoding.UTF8.GetBytes(text));
        return ms.ToArray();
    }

    // ── IpsumLoader ──

    [Fact]
    public async Task Ipsum_TruncatedCache_IsRebuilt()
    {
        string cacheDir = CacheDir();
        string source = SourceFile("ipsum.txt", "1.2.3.4\t5\n"u8.ToArray());
        // Two bytes cannot hold the magic number: BinaryReader throws, the catch resets.
        await File.WriteAllBytesAsync(Path.Combine(cacheDir, "ipsum-v1.bin"), [1, 2]);

        var scores = await new IpsumLoader(cacheDir).LoadAsync(source);

        scores.Should().ContainKey(16909060u).WhoseValue.Should().Be(5);
    }

    [Fact]
    public async Task Ipsum_UnwritableCache_StillReturnsData()
    {
        string cacheDir = CacheDir();
        string source = SourceFile("ipsum.txt", "1.2.3.4\t5\n"u8.ToArray());
        BlockCacheFile(cacheDir, "ipsum-v1.bin");

        var scores = await new IpsumLoader(cacheDir).LoadAsync(source);

        scores.Should().HaveCount(1);
        AssertNoTempLeft(cacheDir);
    }

    // ── Ip2AsnLoader ──

    [Fact]
    public async Task Ip2Asn_TruncatedCache_IsRebuilt()
    {
        string cacheDir = CacheDir();
        string source = SourceFile("ip2asn-v4.tsv.gz", Gzip("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"));
        await File.WriteAllBytesAsync(Path.Combine(cacheDir, "ip2asn-v1.bin"), [1, 2]);

        var records = await new Ip2AsnLoader(cacheDir).LoadAsync(source);

        records.Should().ContainSingle().Which.Asn.Should().Be(13335u);
    }

    [Fact]
    public async Task Ip2Asn_UnwritableCache_StillReturnsData()
    {
        string cacheDir = CacheDir();
        string source = SourceFile("ip2asn-v4.tsv.gz", Gzip("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"));
        BlockCacheFile(cacheDir, "ip2asn-v1.bin");

        var records = await new Ip2AsnLoader(cacheDir).LoadAsync(source);

        records.Should().HaveCount(1);
        AssertNoTempLeft(cacheDir);
    }

    // ── AsnMetadataParser ──

    private const string AsJson =
        """[{"asn":13335,"website":"https://cloudflare.com","organization":"Cloudflare","metadata":{"category":"hosting","networkRole":"transit"},"stats":{"connectivity":{"reach":100}}}]""";

    [Fact]
    public async Task AsnMetadata_TruncatedCache_IsRebuilt()
    {
        string cacheDir = CacheDir();
        string source = SourceFile("as.json", Encoding.UTF8.GetBytes(AsJson));
        await File.WriteAllBytesAsync(Path.Combine(cacheDir, "as-metadata-v1.bin"), [1, 2]);

        var (hosting, byAsn, _) = await new AsnMetadataParser(cacheDir).LoadAllAsync(source);

        hosting.Should().Contain(13335u);
        byAsn[13335].Should().Be("https://cloudflare.com");
    }

    [Fact]
    public async Task AsnMetadata_UnwritableCache_StillReturnsData()
    {
        string cacheDir = CacheDir();
        string source = SourceFile("as.json", Encoding.UTF8.GetBytes(AsJson));
        BlockCacheFile(cacheDir, "as-metadata-v1.bin");

        var (hosting, _, _) = await new AsnMetadataParser(cacheDir).LoadAllAsync(source);

        hosting.Should().Contain(13335u);
        AssertNoTempLeft(cacheDir);
    }

    // ── BgpToolsTagLoader: unreadable file degrades to an empty result ──

    [Fact]
    public async Task BgpTools_LockedFile_YieldsEmptySet()
    {
        string path = Path.Combine(_dir, "vpsh.csv");
        await File.WriteAllTextAsync(path, "AS1,One\n");
        // An exclusive handle makes ReadAllLinesAsync throw IOException on Windows.
        using var _ = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None);

        (await BgpToolsTagLoader.LoadTagAsync(path)).Should().BeEmpty();
        (await BgpToolsTagLoader.LoadTagWithNamesAsync(path)).Should().BeEmpty();
    }
}
