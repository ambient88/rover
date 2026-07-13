using System.IO.Compression;
using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

public class Ip2AsnLoaderCacheTests
{
    private static string WriteGzip(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"ip2asn-c-{Guid.NewGuid():N}.tsv.gz");
        using var fs = File.Create(path);
        using var gz = new GZipStream(fs, CompressionLevel.Fastest);
        using var sw = new StreamWriter(gz);
        sw.Write(content);
        return path;
    }

    [Fact]
    public async Task Load_SecondCall_ReadsFromCache()
    {
        var path = WriteGzip("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n");
        try
        {
            var loader = new Ip2AsnLoader();
            (await loader.LoadAsync(path)).Should().ContainSingle(); // builds + writes cache
            (await loader.LoadAsync(path)).Should().ContainSingle(); // reads cache
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Load_SkipsIpv6AndUnparsableRows()
    {
        var path = WriteGzip(
            "2001:db8::\t2001:db8::ff\t100\tUS\tV6NET\n" +   // IPv6 → skipped
            "notanip\twhatever\t200\tUS\tGARBAGE\n" +         // unparsable → skipped
            "1.0.0.0\t1.0.0.255\t300\tUS\tGOODNET\n");        // valid IPv4
        try
        {
            var records = await new Ip2AsnLoader().LoadAsync(path);
            records.Should().OnlyContain(r => r.Asn == 300u);
        }
        finally { File.Delete(path); }
    }
}
