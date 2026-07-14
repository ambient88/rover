using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

// IPsum parses IP and score TSV rows while skipping hash-prefixed comments.
// The checker returns a score for a numeric IP or null when none exists.
public class IpsumTests
{
    private static string TempFile(string body)
    {
        var p = Path.Combine(Path.GetTempPath(), $"ipsum-{Guid.NewGuid():N}.txt");
        File.WriteAllText(p, body);
        return p;
    }

    private static uint Ip(string dotted)
    {
        var b = System.Net.IPAddress.Parse(dotted).GetAddressBytes();
        return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
    }

    [Fact]
    public async Task Load_ParsesValidEntries()
    {
        var path = TempFile("1.2.3.4\t5\n8.8.8.8\t9\n");
        try
        {
            var map = await new IpsumLoader().LoadAsync(path);

            map.Should().HaveCount(2);
            map[Ip("1.2.3.4")].Should().Be(5);
            map[Ip("8.8.8.8")].Should().Be(9);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Load_SkipsCommentsBlankAndMalformedLines()
    {
        var path = TempFile(
            "# Ipsum threat list\n" +
            "\n" +
            "9.9.9.9\t3\n" +
            "no-tab-here 4\n" +          // Missing tab separator.
            "not.an.ip\t7\n" +           // Invalid IP address.
            "10.0.0.1\tnotanumber\n");   // Score is not numeric.
        try
        {
            var map = await new IpsumLoader().LoadAsync(path);

            map.Should().ContainSingle().Which.Key.Should().Be(Ip("9.9.9.9"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Load_SkipsIpv6() // Only IPv4 addresses are supported.
    {
        var path = TempFile("2001:db8::1\t5\n1.2.3.4\t2\n");
        try
        {
            var map = await new IpsumLoader().LoadAsync(path);

            map.Should().ContainSingle().Which.Key.Should().Be(Ip("1.2.3.4"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Load_MissingFile_ReturnsEmpty()
    {
        var map = await new IpsumLoader().LoadAsync(
            Path.Combine(Path.GetTempPath(), $"nonexistent-{Guid.NewGuid():N}.txt"));

        map.Should().BeEmpty();
    }

    [Fact]
    public void Checker_ReturnsScoreForKnownIp()
    {
        var checker = new IpsumReputationChecker(new Dictionary<uint, int> { [Ip("1.2.3.4")] = 7 });

        checker.Check(Ip("1.2.3.4")).Should().Be(7);
    }

    [Fact]
    public void Checker_ReturnsNullForUnknownIp()
    {
        var checker = new IpsumReputationChecker(new Dictionary<uint, int> { [Ip("1.2.3.4")] = 7 });

        checker.Check(Ip("9.9.9.9")).Should().BeNull();
    }

    [Fact]
    public async Task Load_SourceChange_InvalidatesCache()
    {
        var path = TempFile("1.2.3.4\t2\n");
        var cacheDir = Path.Combine(Path.GetTempPath(), $"ipsum-cache-{Guid.NewGuid():N}");
        try
        {
            var loader = new IpsumLoader(cacheDir);
            (await loader.LoadAsync(path))[Ip("1.2.3.4")].Should().Be(2);
            await File.WriteAllTextAsync(path, "1.2.3.4\t9\n");
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddSeconds(2));

            var scores = await loader.LoadAsync(path);

            scores[Ip("1.2.3.4")].Should().Be(9);
        }
        finally
        {
            File.Delete(path);
            if (Directory.Exists(cacheDir)) Directory.Delete(cacheDir, true);
        }
    }
}
