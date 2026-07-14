using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Covers IPv4 extraction, ASN aggregation through the ip2asn index, reserved address filtering,
// and local .txt or .csv sources.
public class IpListAnalyzerAggregateTests
{
    private static Ip2AsnRecord Rec(string start, string end, uint asn) => new()
    {
        StartIp = IpConverter.IpToUint(start),
        EndIp   = IpConverter.IpToUint(end),
        Asn     = asn, Country = "US", Description = $"AS{asn}",
    };

    private static IpRangeIndex Index() => new(new[]
    {
        Rec("8.8.8.0", "8.8.8.255", 15169),
        Rec("1.1.1.0", "1.1.1.255", 13335),
    });

    // ExtractIps tests.

    [Fact]
    public void ExtractIps_ExtractsAndDeduplicates()
    {
        var ips = IpListAnalyzer.ExtractIps("host 8.8.8.8 then 8.8.8.8 and 1.1.1.1 done");

        ips.Should().BeEquivalentTo(new[] { "8.8.8.8", "1.1.1.1" });
    }

    [Fact]
    public void ExtractIps_NoIps_ReturnsEmpty()
        => IpListAnalyzer.ExtractIps("no addresses here").Should().BeEmpty();

    // AggregateByAsn tests.

    [Fact]
    public void AggregateByAsn_CountsAndSortsDescending()
    {
        var ips = new[] { "8.8.8.8", "8.8.8.9", "1.1.1.1" };

        var agg = IpListAnalyzer.AggregateByAsn(ips, Index());

        agg.Should().HaveCount(2);
        agg[0].Should().Be((15169u, 2), "самый частый ASN первым");
        agg[1].Should().Be((13335u, 1));
    }

    [Fact]
    public void AggregateByAsn_SkipsPrivateReservedAndUnmapped()
    {
        var ips = new[]
        {
            "8.8.8.8",        // Maps to AS15169.
            "10.0.0.1",       // RFC1918 private
            "192.168.1.1",    // RFC1918 private
            "127.0.0.1",      // loopback
            "169.254.1.1",    // link-local / metadata
            "203.0.113.5",    // TEST-NET-3
            "9.9.9.9",        // Public but absent from the index.
        };

        var agg = IpListAnalyzer.AggregateByAsn(ips, Index());

        agg.Should().ContainSingle().Which.Should().Be((15169u, 1));
    }

    [Fact]
    public void AggregateByAsn_InvalidIpStrings_AreIgnored()
    {
        var agg = IpListAnalyzer.AggregateByAsn(new[] { "not-an-ip", "8.8.8.8" }, Index());

        agg.Should().ContainSingle().Which.Asn.Should().Be(15169u);
    }

    // Local file sources for ReadSourceAsync.

    [Fact]
    public async Task ReadSource_TxtFile_ReturnsContent()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ips-{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(path, "1.2.3.4\n5.6.7.8");
        try
        {
            using var http = new HttpClient();
            var text = await IpListAnalyzer.ReadSourceAsync(path, http);

            text.Should().Contain("1.2.3.4");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task ReadSource_CsvFile_ReturnsContent()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ips-{Guid.NewGuid():N}.csv");
        await File.WriteAllTextAsync(path, "ip\n1.2.3.4");
        try
        {
            using var http = new HttpClient();
            (await IpListAnalyzer.ReadSourceAsync(path, http)).Should().Contain("1.2.3.4");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task ReadSource_DisallowedExtension_Throws()
    {
        var path = Path.Combine(Path.GetTempPath(), $"secret-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, "{}");
        try
        {
            using var http = new HttpClient();
            Func<Task> act = () => IpListAnalyzer.ReadSourceAsync(path, http);
            await act.Should().ThrowAsync<ArgumentException>();
        }
        finally { File.Delete(path); }
    }
}
