using System.IO.Compression;
using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Tests;

// Ip2AsnLoader: разбор gzip-TSV ip2asn (start end asn country descr), пропуск комментариев
// и коротких строк; пустой результат → InvalidDataException.
public class Ip2AsnLoaderTests
{
    private static string WriteGzip(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"ip2asn-{Guid.NewGuid():N}.tsv.gz");
        using var fs = File.Create(path);
        using var gz = new GZipStream(fs, CompressionLevel.Fastest);
        using var sw = new StreamWriter(gz);
        sw.Write(content);
        return path;
    }

    [Fact]
    public async Task Load_ParsesRecords()
    {
        var path = WriteGzip(
            "# comment line\n" +
            "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
            "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n");
        try
        {
            var records = await new Ip2AsnLoader().LoadAsync(path);

            records.Should().HaveCount(2);
            var cf = records[0];
            cf.Asn.Should().Be(13335u);
            cf.Country.Should().Be("US");
            cf.Description.Should().Be("CLOUDFLARENET");
            cf.StartIp.Should().Be(IpConverter.IpToUint("1.0.0.0"));
            cf.EndIp.Should().Be(IpConverter.IpToUint("1.0.0.255"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Load_SkipsShortAndNonNumericAsnLines()
    {
        var path = WriteGzip(
            "1.0.0.0\t1.0.0.255\t13335\tUS\tOK\n" +
            "too\tshort\n" +                        // < 5 колонок
            "2.0.0.0\t2.0.0.255\tNaN\tUS\tBadAsn\n"); // нечисловой ASN
        try
        {
            var records = await new Ip2AsnLoader().LoadAsync(path);

            records.Should().ContainSingle().Which.Asn.Should().Be(13335u);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Load_NoRecords_ThrowsInvalidData() // краевой случай: файл есть, данных нет
    {
        var path = WriteGzip("# only a header\n# nothing else\n");
        try
        {
            await new Ip2AsnLoader().Invoking(l => l.LoadAsync(path))
                .Should().ThrowAsync<InvalidDataException>();
        }
        finally { File.Delete(path); }
    }
}
