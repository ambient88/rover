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

    // Стаб хранилища: считает валидными файлы из заданного множества.
    private sealed class StubStorage : IFileStorage
    {
        private readonly HashSet<string> _valid;
        public StubStorage(params string[] valid) => _valid = new(valid);
        public bool IsFileValid(string fileName, long minSize) => _valid.Contains(fileName);
        public Task SaveAsync(string f, Stream c, CancellationToken ct = default) => Task.CompletedTask;
    }

    [Theory]
    // isUpdate, anyFileValid, anyPending → ожидаемый режим
    [InlineData(true,  true,  true,  ProvisioningMode.Visible)]  // update всегда Visible
    [InlineData(true,  true,  false, ProvisioningMode.Visible)]  // update даже когда всё свежее
    [InlineData(true,  false, true,  ProvisioningMode.Visible)]
    [InlineData(false, false, true,  ProvisioningMode.Visible)]  // первый запуск — нет валидных файлов
    [InlineData(false, false, false, ProvisioningMode.Visible)]  // нет валидных → Visible
    [InlineData(false, true,  true,  ProvisioningMode.Silent)]   // есть данные + что-то устарело
    [InlineData(false, true,  false, ProvisioningMode.None)]     // всё свежее — тишина
    public void Decide_SelectsMode(bool isUpdate, bool anyFileValid, bool anyPending, ProvisioningMode expected)
        => ProvisioningStatus.Decide(isUpdate, anyFileValid, anyPending).Should().Be(expected);

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
    public void AnyPending_MissingFile_IsPending()
    {
        var files = new[] { new FileDescriptor("u", "missing.bin") };

        Make(new StubStorage(/* пусто → файл невалиден */), files).AnyPending().Should().BeTrue();
    }

    [Fact]
    public void AnyPending_ValidDownloadOnceFile_NotPending()
    {
        // MaxAge=null → download-once: валидный файл больше не требует загрузки.
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
