using FluentAssertions;
using SubnetSearch.Core.Interfaces.Data;
using SubnetSearch.Core.Models.Data;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

public class ProvisioningStatusTests : IDisposable
{
    private readonly string _dir;
    public ProvisioningStatusTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"prov-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
    }
    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    // The storage stub treats files from the supplied set as valid.
    private sealed class StubStorage : IFileStorage
    {
        private readonly HashSet<string> _valid;
        public StubStorage(params string[] valid) => _valid = new(valid);
        public bool IsFileValid(string fileName, long minSize) => _valid.Contains(fileName);
        public Task SaveAsync(string f, Stream c, CancellationToken ct = default) => Task.CompletedTask;
    }

    [Theory]
    // isUpdate, anyFileValid, anyFileInvalid, expected mode
    [InlineData(true,  true,  true,  ProvisioningMode.Visible)]  // Updates are always visible.
    [InlineData(true,  true,  false, ProvisioningMode.Visible)]  // Fresh data does not hide an explicit update.
    [InlineData(true,  false, true,  ProvisioningMode.Visible)]
    [InlineData(false, false, true,  ProvisioningMode.Visible)]  // First run without valid files.
    [InlineData(false, false, false, ProvisioningMode.Visible)]  // Missing valid data remains visible.
    [InlineData(false, true,  true,  ProvisioningMode.Silent)]   // Existing data allows a silent refresh.
    [InlineData(false, true,  false, ProvisioningMode.None)]     // Fresh data needs no provisioning.
    public void Decide_SelectsMode(bool isUpdate, bool anyFileValid, bool anyFileInvalid, ProvisioningMode expected)
        => ProvisioningStatus.Decide(isUpdate, anyFileValid, anyFileInvalid).Should().Be(expected);

    private ProvisioningStatus Make(IFileStorage storage, params FileDescriptor[] files)
        => new(storage, files, new FileMetadataStore(_dir));

    [Fact]
    public void AnyFileValid_TrueWhenAtLeastOnePresent()
    {
        var files = new[] { new FileDescriptor("u1", "a.bin"), new FileDescriptor("u2", "b.bin") };

        Make(new StubStorage("a.bin"), files).AnyFileValid().Should().BeTrue();
        Make(new StubStorage(), files).AnyFileValid().Should().BeFalse("нет ни одного валидного файла");
    }

    [Fact]
    public void AnyFileInvalid_TrueWhenAtLeastOneFileIsMissing()
    {
        var files = new[] { new FileDescriptor("u1", "a.bin"), new FileDescriptor("u2", "b.bin") };

        Make(new StubStorage("a.bin"), files).AnyFileInvalid().Should().BeTrue();
        Make(new StubStorage("a.bin", "b.bin"), files).AnyFileInvalid().Should().BeFalse();
    }

    [Fact]
    public void AnyPending_MissingFile_IsPending()
    {
        var files = new[] { new FileDescriptor("u", "missing.bin") };

        Make(new StubStorage(/* Empty set means every file is invalid. */), files).AnyPending().Should().BeTrue();
    }

    [Fact]
    public void AnyPending_ValidDownloadOnceFile_NotPending()
    {
        // A null MaxAge gives a valid file download-once behavior.
        var files = new[] { new FileDescriptor("u", "once.bin", MaxAge: null) };

        Make(new StubStorage("once.bin"), files).AnyPending().Should().BeFalse();
    }

    [Fact]
    public void AnyPending_ValidButStaleByTtl_IsPending()
    {
        var meta = new FileMetadataStore(_dir);
        meta.Save("ttl.bin", new FileMetadata(DateTimeOffset.UtcNow - TimeSpan.FromDays(3)));
        var status = new ProvisioningStatus(
            new StubStorage("ttl.bin"),
            new[] { new FileDescriptor("u", "ttl.bin", MaxAge: TimeSpan.FromDays(1)) },
            meta);

        status.AnyPending().Should().BeTrue("TTL истёк → нужен рефреш");
    }

    [Fact]
    public void AnyPending_ValidAndFreshByTtl_NotPending()
    {
        var meta = new FileMetadataStore(_dir);
        meta.Save("fresh.bin", new FileMetadata(DateTimeOffset.UtcNow));
        var status = new ProvisioningStatus(
            new StubStorage("fresh.bin"),
            new[] { new FileDescriptor("u", "fresh.bin", MaxAge: TimeSpan.FromDays(1)) },
            meta);

        status.AnyPending().Should().BeFalse();
    }
}
