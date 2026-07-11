using System.Text;
using FluentAssertions;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

// ProgressStream: read-only обёртка, репортящая накопленный объём прочитанного;
// запись/seek/flush не поддерживаются.
public class ProgressStreamTests
{
    private static MemoryStream Source(int bytes) => new(Encoding.ASCII.GetBytes(new string('x', bytes)));

    [Fact]
    public void Read_ReportsCumulativeProgress()
    {
        var progress = new List<long>();
        using var ps = new ProgressStream(Source(10), progress.Add);

        var buf = new byte[4];
        ps.Read(buf, 0, 4);
        ps.Read(buf, 0, 4);
        ps.Read(buf, 0, 4); // осталось 2 байта

        progress.Should().Equal(4, 8, 10);
    }

    [Fact]
    public async Task ReadAsync_ReportsCumulativeProgress()
    {
        var progress = new List<long>();
        await using var ps = new ProgressStream(Source(6), progress.Add);

        var buf = new byte[4];
        await ps.ReadAsync(buf, 0, 4);
        await ps.ReadAsync(buf, 0, 4);

        progress.Should().Equal(4, 6);
    }

    [Fact]
    public void Read_AtEnd_DoesNotReport() // краевой случай: чтение за концом → 0 байт
    {
        var progress = new List<long>();
        using var ps = new ProgressStream(Source(2), progress.Add);

        var buf = new byte[8];
        ps.Read(buf, 0, 8); // читает 2
        ps.Read(buf, 0, 8); // читает 0 — репорта нет

        progress.Should().Equal(2);
    }

    [Fact]
    public void Properties_ReflectReadOnlyBaseStream()
    {
        using var ps = new ProgressStream(Source(5), _ => { });

        ps.CanRead.Should().BeTrue();
        ps.CanSeek.Should().BeFalse();
        ps.CanWrite.Should().BeFalse();
        ps.Length.Should().Be(5);
    }

    [Fact]
    public void UnsupportedOperations_Throw()
    {
        using var ps = new ProgressStream(Source(5), _ => { });

        ps.Invoking(s => s.Flush()).Should().Throw<NotSupportedException>();
        ps.Invoking(s => s.SetLength(1)).Should().Throw<NotSupportedException>();
        ps.Invoking(s => s.Write(new byte[1], 0, 1)).Should().Throw<NotSupportedException>();
        ps.Invoking(s => s.Seek(0, SeekOrigin.Begin)).Should().Throw<NotSupportedException>();
        ps.Invoking(s => { _ = s.Position; s.Position = 1; }).Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void Constructor_NullArguments_Throw()
    {
        FluentActions.Invoking(() => new ProgressStream(null!, _ => { }))
            .Should().Throw<ArgumentNullException>();
        FluentActions.Invoking(() => new ProgressStream(Source(1), null!))
            .Should().Throw<ArgumentNullException>();
    }
}
