using System.IO.Compression;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using SubnetSearch.Core.Interfaces.Data;
using SubnetSearch.Core.Utilities;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

// Covers safe storage paths, validation, atomic writes, metadata freshness, and format integrity checks.
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

    private sealed class ConcurrencyChecker : IFileIntegrityChecker, IDisposable
    {
        private int _active;
        private readonly CountdownEvent _arrived = new(2);
        private readonly ManualResetEventSlim _release = new(false);
        public int MaxActive { get; private set; }

        public bool IsValid(string filePath)
        {
            int active = Interlocked.Increment(ref _active);
            lock (this) MaxActive = Math.Max(MaxActive, active);
            _arrived.Signal();
            _release.Wait(TimeSpan.FromSeconds(5));
            Interlocked.Decrement(ref _active);
            return true;
        }

        public bool WaitForBoth(TimeSpan timeout) => _arrived.Wait(timeout);

        public void Release() => _release.Set();

        public void Dispose()
        {
            _release.Dispose();
            _arrived.Dispose();
        }
    }

    private sealed class MutatingChecker : IFileIntegrityChecker
    {
        public bool IsValid(string filePath)
        {
            // Simulates a concurrent writer touching the file while it is being validated.
            File.AppendAllText(filePath, "!");
            return true;
        }
    }

    private sealed class FailingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => 0; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
            => throw new IOException("stream failed mid-copy");
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public void Storage_BlankFileName_Throws()
    {
        var storage = new LocalFileStorage(_dir);

        storage.Invoking(s => s.IsFileValid("   ", 0)).Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Storage_FileModifiedDuringValidation_IsRejected()
    {
        File.WriteAllText(Path.Combine(_dir, "racy.chk"), "valid");
        var storage = new LocalFileStorage(_dir,
            new Dictionary<string, IFileIntegrityChecker> { [".chk"] = new MutatingChecker() });

        storage.IsFileValid("racy.chk", 0)
            .Should().BeFalse("the file changed under the checker, so its verdict cannot be trusted");
    }

    [Fact]
    public async Task Storage_Save_FailingSource_CleansTempAndRethrows()
    {
        var storage = new LocalFileStorage(_dir);

        var act = () => storage.SaveAsync("broken.bin", new FailingStream());

        await act.Should().ThrowAsync<IOException>();
        File.Exists(Path.Combine(_dir, "broken.bin.tmp")).Should().BeFalse();
    }

    [Fact]
    public void Storage_CorruptIntegritySnapshot_FallsBackToFullCheck()
    {
        File.WriteAllText(Path.Combine(_dir, "v.chk"), "valid");
        File.WriteAllText(Path.Combine(_dir, "v.chk.integrity.json"), "{ broken");
        var checker = new CountingChecker();
        var storage = new LocalFileStorage(_dir,
            new Dictionary<string, IFileIntegrityChecker> { [".chk"] = checker });

        storage.IsFileValid("v.chk", 0).Should().BeTrue();
        checker.Calls.Should().Be(1, "an unreadable snapshot forces one real validation");
    }

    [Fact]
    public void Storage_LegacySnapshotFromDifferentChecker_IsIgnored()
    {
        string filePath = Path.Combine(_dir, "v.chk");
        File.WriteAllText(filePath, "valid");
        var info = new FileInfo(filePath);
        // Length and timestamp match, but the version belongs to another checker type.
        File.WriteAllText(filePath + ".integrity.json", JsonSerializer.Serialize(new
        {
            Length = info.Length,
            LastWriteTimeUtcTicks = info.LastWriteTimeUtc.Ticks,
            CheckerVersion = "Some.Other.Checker:00112233445566778899aabbccddeeff",
        }));
        var checker = new CountingChecker();
        var storage = new LocalFileStorage(_dir,
            new Dictionary<string, IFileIntegrityChecker> { [".chk"] = checker });

        storage.IsFileValid("v.chk", 0).Should().BeTrue();
        checker.Calls.Should().Be(1, "a foreign checker's snapshot must not be trusted");
    }

    [Fact]
    public async Task Storage_Save_LockedStaleSnapshot_StillSaves()
    {
        string snapshotPath = Path.Combine(_dir, "locked.bin.integrity.json");
        File.WriteAllText(snapshotPath, "{}");
        // An exclusive handle makes the snapshot delete fail; the save must proceed anyway.
        using var lockHandle = new FileStream(
            snapshotPath, FileMode.Open, FileAccess.Read, FileShare.None);
        var storage = new LocalFileStorage(_dir);

        await storage.SaveAsync("locked.bin", Bytes("payload"));

        File.ReadAllText(Path.Combine(_dir, "locked.bin")).Should().Be("payload");
    }

    // LocalFileStorage tests.

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
        using var checker = new ConcurrencyChecker();
        var storage = new LocalFileStorage(
            _dir,
            new Dictionary<string, IFileIntegrityChecker> { [".test"] = checker });

        Task first = Task.Factory.StartNew(
                () => storage.IsFileValid("first.test", 0),
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
        Task second = Task.Factory.StartNew(
                () => storage.IsFileValid("second.test", 0),
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);

        bool bothArrived = checker.WaitForBoth(TimeSpan.FromSeconds(2));
        checker.Release();
        await Task.WhenAll(first, second);

        bothArrived.Should().BeTrue();
        checker.MaxActive.Should().Be(2);
    }

    [Fact]
    public void Storage_RejectsPathTraversal()
    {
        var storage = new LocalFileStorage(_dir);

        storage.Invoking(s => s.IsFileValid("../escape.txt", 0))
            .Should().Throw<ArgumentException>();
    }

    // FileMetadataStore tests.

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
    public void Metadata_Load_Corrupt_ReturnsNull()
    {
        File.WriteAllText(Path.Combine(_dir, "x.bin.meta.json"), "{ not json ]");

        new FileMetadataStore(_dir).Load("x.bin").Should().BeNull();
    }

    [Fact]
    public void Metadata_Save_UnwritableDirectory_IsBestEffort()
    {
        var store = new FileMetadataStore(Path.Combine(_dir, "missing-subdir"));

        // Metadata loss only causes a re-download next run, so a failed save must not throw.
        var act = () => store.Save("f.bin", new FileMetadata(DateTimeOffset.UtcNow));

        act.Should().NotThrow();
        store.Load("f.bin").Should().BeNull();
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

    // Integrity checker tests.

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

    // A truncated archive can decompress its first byte while still lacking a valid gzip
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
