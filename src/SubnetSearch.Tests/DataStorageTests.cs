using System.IO.Compression;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using SubnetSearch.Core.Interfaces.Data;
using SubnetSearch.Core.Utilities;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

// Storage-слой Data: LocalFileStorage (безопасные пути, валидация, атомарная запись),
// FileMetadataStore (round-trip, staleness) и проверки целостности (gzip/json/zip).
public class DataStorageTests : IDisposable
{
    private readonly string _dir;

    public DataStorageTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"store-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
    }

    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    private static Stream Bytes(string s) => new MemoryStream(Encoding.UTF8.GetBytes(s));

    private sealed class CountingChecker : IFileIntegrityChecker
    {
        public int Calls { get; private set; }

        public bool IsValid(string filePath)
        {
            Calls++;
            return File.ReadAllText(filePath) == "valid";
        }
    }

    private sealed class ConcurrencyChecker : IFileIntegrityChecker
    {
        private int _active;
        public int MaxActive { get; private set; }

        public bool IsValid(string filePath)
        {
            int active = Interlocked.Increment(ref _active);
            lock (this) MaxActive = Math.Max(MaxActive, active);
            Thread.Sleep(50);
            Interlocked.Decrement(ref _active);
            return true;
        }
    }

    // ── LocalFileStorage ──

    [Fact]
    public async Task Storage_Save_WritesFile()
    {
        var storage = new LocalFileStorage(_dir);
        await storage.SaveAsync("data.txt", Bytes("hello"));

        File.ReadAllText(Path.Combine(_dir, "data.txt")).Should().Be("hello");
    }

    [Fact]
    public async Task Storage_Save_IsAtomic_NoLeftoverTemp()
    {
        var storage = new LocalFileStorage(_dir);
        await storage.SaveAsync("data.txt", Bytes("hi"));

        File.Exists(Path.Combine(_dir, "data.txt.tmp")).Should().BeFalse();
    }

    [Fact]
    public void Storage_IsFileValid_MissingFile_False()
        => new LocalFileStorage(_dir).IsFileValid("nope.txt", minSize: 0).Should().BeFalse();

    [Fact]
    public async Task Storage_IsFileValid_TooSmall_False()
    {
        var storage = new LocalFileStorage(_dir);
        await storage.SaveAsync("small.txt", Bytes("ab"));

        storage.IsFileValid("small.txt", minSize: 100).Should().BeFalse();
    }

    [Fact]
    public async Task Storage_IsFileValid_NoChecker_TrueWhenSizeOk()
    {
        var storage = new LocalFileStorage(_dir);
        await storage.SaveAsync("ok.txt", Bytes("enough-bytes"));

        storage.IsFileValid("ok.txt", minSize: 1).Should().BeTrue();
    }

    [Fact]
    public async Task Storage_IsFileValid_UsesRegisteredChecker()
    {
        var checkers = new Dictionary<string, IFileIntegrityChecker> { [".json"] = new JsonIntegrityChecker() };
        var storage = new LocalFileStorage(_dir, checkers);

        await storage.SaveAsync("good.json", Bytes("""{"ok":true}"""));
        await storage.SaveAsync("bad.json", Bytes("{ broken"));

        storage.IsFileValid("good.json", 0).Should().BeTrue();
        storage.IsFileValid("bad.json", 0).Should().BeFalse("checker отвергает битый JSON");
    }

    [Fact]
    public void Storage_IntegritySnapshot_SkipsUnchangedFileAndRechecksChangedFile()
    {
        string path = Path.Combine(_dir, "large.test");
        File.WriteAllText(path, "valid");
        var checker = new CountingChecker();
        var checkers = new Dictionary<string, IFileIntegrityChecker> { [".test"] = checker };

        new LocalFileStorage(_dir, checkers).IsFileValid("large.test", 0).Should().BeTrue();
        new LocalFileStorage(_dir, checkers).IsFileValid("large.test", 0).Should().BeTrue();
        checker.Calls.Should().Be(1);

        File.WriteAllText(path, "other");
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddSeconds(1));

        new LocalFileStorage(_dir, checkers).IsFileValid("large.test", 0).Should().BeFalse();
        checker.Calls.Should().Be(2);
    }

    [Fact]
    public void Storage_IntegritySnapshotFallsBackWhenDataDirectoryIsNotWritable()
    {
        string path = Path.Combine(_dir, "fallback.test");
        string primarySnapshot = path + ".integrity.json";
        File.WriteAllText(path, "valid");
        Directory.CreateDirectory(primarySnapshot);
        var checker = new CountingChecker();
        var checkers = new Dictionary<string, IFileIntegrityChecker> { [".test"] = checker };
        string fallbackDirectory = DerivedCachePath.ForDataDirectory(_dir, "integrity");

        try
        {
            new LocalFileStorage(_dir, checkers).IsFileValid("fallback.test", 0).Should().BeTrue();
            new LocalFileStorage(_dir, checkers).IsFileValid("fallback.test", 0).Should().BeTrue();

            checker.Calls.Should().Be(1);
            File.Exists(Path.Combine(fallbackDirectory, "fallback.test.integrity.json"))
                .Should().BeTrue();
        }
        finally
        {
            if (Directory.Exists(fallbackDirectory))
                Directory.Delete(fallbackDirectory, true);
        }
    }

    [Fact]
    public void Storage_LegacySnapshotMigratesWithoutRecheckingFile()
    {
        string path = Path.Combine(_dir, "legacy.test");
        File.WriteAllText(path, "valid");
        var info = new FileInfo(path);
        var checker = new CountingChecker();
        string checkerType = checker.GetType().FullName!;
        File.WriteAllText(path + ".integrity.json", JsonSerializer.Serialize(new
        {
            Length = info.Length,
            LastWriteTimeUtcTicks = info.LastWriteTimeUtc.Ticks,
            CheckerVersion = checkerType + ":0123456789ABCDEF0123456789ABCDEF"
        }));
        var storage = new LocalFileStorage(
            _dir,
            new Dictionary<string, IFileIntegrityChecker> { [".test"] = checker });

        storage.IsFileValid("legacy.test", 0).Should().BeTrue();

        checker.Calls.Should().Be(0);
        using var migrated = JsonDocument.Parse(File.ReadAllText(path + ".integrity.json"));
        migrated.RootElement.GetProperty("CheckerVersion").GetString()
            .Should().Be(checkerType + ":1");
    }

    [Fact]
    public async Task Storage_DifferentFilesAreValidatedConcurrently()
    {
        File.WriteAllText(Path.Combine(_dir, "first.test"), "first");
        File.WriteAllText(Path.Combine(_dir, "second.test"), "second");
        var checker = new ConcurrencyChecker();
        var storage = new LocalFileStorage(
            _dir,
            new Dictionary<string, IFileIntegrityChecker> { [".test"] = checker });

        await Task.WhenAll(
            Task.Factory.StartNew(
                () => storage.IsFileValid("first.test", 0),
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default),
            Task.Factory.StartNew(
                () => storage.IsFileValid("second.test", 0),
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default));

        checker.MaxActive.Should().Be(2);
    }

    [Fact]
    public void Storage_RejectsPathTraversal()
    {
        var storage = new LocalFileStorage(_dir);

        storage.Invoking(s => s.IsFileValid("../escape.txt", 0))
            .Should().Throw<ArgumentException>();
    }

    // ── FileMetadataStore ──

    [Fact]
    public void Metadata_SaveThenLoad_RoundTrips()
    {
        var store = new FileMetadataStore(_dir);
        var meta = new FileMetadata(DateTimeOffset.UtcNow, ETag: "abc", LastModified: "Mon");

        store.Save("file.bin", meta);
        var loaded = store.Load("file.bin");

        loaded.Should().NotBeNull();
        loaded!.ETag.Should().Be("abc");
        loaded.LastModified.Should().Be("Mon");
    }

    [Fact]
    public void Metadata_Load_Missing_ReturnsNull()
        => new FileMetadataStore(_dir).Load("absent.bin").Should().BeNull();

    [Fact]
    public void Metadata_Load_Corrupt_ReturnsNull() // краевой случай: битый meta-файл
    {
        File.WriteAllText(Path.Combine(_dir, "x.bin.meta.json"), "{ not json ]");

        new FileMetadataStore(_dir).Load("x.bin").Should().BeNull();
    }

    [Fact]
    public void Metadata_IsStale_NoMeta_True()
        => new FileMetadataStore(_dir).IsStale("absent.bin", TimeSpan.FromDays(1)).Should().BeTrue();

    [Fact]
    public void Metadata_IsStale_FreshEntry_False()
    {
        var store = new FileMetadataStore(_dir);
        store.Save("f.bin", new FileMetadata(DateTimeOffset.UtcNow));

        store.IsStale("f.bin", TimeSpan.FromHours(1)).Should().BeFalse();
    }

    [Fact]
    public void Metadata_IsStale_OldEntry_True()
    {
        var store = new FileMetadataStore(_dir);
        store.Save("f.bin", new FileMetadata(DateTimeOffset.UtcNow - TimeSpan.FromDays(2)));

        store.IsStale("f.bin", TimeSpan.FromDays(1)).Should().BeTrue();
    }

    // ── Integrity checkers ──

    [Fact]
    public void GZipChecker_ValidGzip_True()
    {
        var path = Path.Combine(_dir, "a.gz");
        using (var fs = File.Create(path))
        using (var gz = new GZipStream(fs, CompressionLevel.Fastest))
            gz.Write(Encoding.UTF8.GetBytes("payload"));

        new GZipIntegrityChecker().IsValid(path).Should().BeTrue();
    }

    [Fact]
    public void GZipChecker_NotGzip_False()
    {
        var path = Path.Combine(_dir, "a.gz");
        File.WriteAllText(path, "this is not gzip");

        new GZipIntegrityChecker().IsValid(path).Should().BeFalse();
    }

    // F8 regression: a truncated archive decompresses its first byte fine but has no valid gzip
    // trailer. The old one-byte check waved it through; a full read must reject it. Incompressible
    // random data ensures the truncation cuts the deflate body mid-block (a guaranteed decode error).
    [Fact]
    public void GZipChecker_TruncatedGzip_False()
    {
        var path = Path.Combine(_dir, "trunc.gz");
        var payload = new byte[8000];
        new Random(1234).NextBytes(payload);
        using (var fs = File.Create(path))
        using (var gz = new GZipStream(fs, CompressionLevel.Fastest))
            gz.Write(payload);

        // Drop the trailing half (removes the CRC32/ISIZE trailer and part of the deflate body).
        var bytes = File.ReadAllBytes(path);
        File.WriteAllBytes(path, bytes[..(bytes.Length / 2)]);

        new GZipIntegrityChecker().IsValid(path).Should().BeFalse();
    }

    [Fact]
    public void JsonChecker_ValidJson_True()
    {
        var path = Path.Combine(_dir, "a.json");
        File.WriteAllText(path, """{"x":[1,2,3]}""");

        new JsonIntegrityChecker().IsValid(path).Should().BeTrue();
    }

    [Fact]
    public void JsonChecker_Garbage_False()
    {
        var path = Path.Combine(_dir, "a.json");
        File.WriteAllText(path, "{ not json ]");

        new JsonIntegrityChecker().IsValid(path).Should().BeFalse();
    }

    [Fact]
    public void ZipChecker_ValidZip_True()
    {
        var path = Path.Combine(_dir, "a.zip");
        using (var fs = File.Create(path))
        using (var archive = new ZipArchive(fs, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("inner.txt");
            using var w = new StreamWriter(entry.Open());
            w.Write("data");
        }

        new ZipIntegrityChecker().IsValid(path).Should().BeTrue();
    }

    [Fact]
    public void ZipChecker_NotZip_False()
    {
        var path = Path.Combine(_dir, "a.zip");
        File.WriteAllText(path, "not a zip archive");

        new ZipIntegrityChecker().IsValid(path).Should().BeFalse();
    }
}
