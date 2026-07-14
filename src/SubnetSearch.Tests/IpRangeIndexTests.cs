using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Tests;

// IpRangeIndex uses binary search to find an ASN record in sorted numeric IP ranges.
public class IpRangeIndexTests
{
    private static Ip2AsnRecord Rec(string start, string end, uint asn) => new()
    {
        StartIp = IpConverter.IpToUint(start),
        EndIp   = IpConverter.IpToUint(end),
        Asn     = asn,
        Country = "US",
        Description = $"AS{asn}",
    };

    private static IpRangeIndex Index() => new(new[]
    {
        Rec("8.8.8.0",  "8.8.8.255",  15169),
        Rec("1.0.0.0",  "1.0.0.255",  13335),   // The index sorts out-of-order input.
        Rec("10.0.0.0", "10.255.255.255", 64512),
    });

    [Theory]
    [InlineData("1.0.0.128",  13335)]
    [InlineData("8.8.8.8",    15169)]
    [InlineData("10.5.6.7",   64512)]
    public void Find_IpInsideRange_ReturnsRecord(string ip, uint expectedAsn)
    {
        var rec = Index().Find(IpConverter.IpToUint(ip));
        rec.HasValue.Should().BeTrue();
        rec!.Value.Asn.Should().Be(expectedAsn);
    }

    [Theory]
    [InlineData("1.0.0.0")]     // Lower boundary.
    [InlineData("1.0.0.255")]   // Upper boundary.
    public void Find_BoundaryAddresses_AreInclusive(string ip)
    {
        var rec = Index().Find(IpConverter.IpToUint(ip));
        rec.HasValue.Should().BeTrue();
        rec!.Value.Asn.Should().Be(13335u);
    }

    [Theory]
    [InlineData("9.9.9.9")]     // Between ranges.
    [InlineData("255.255.255.255")]
    public void Find_IpOutsideAnyRange_ReturnsNull(string ip)
        => Index().Find(IpConverter.IpToUint(ip)).Should().BeNull();

    [Fact]
    public void Find_EmptyIndex_ReturnsNull()
        => new IpRangeIndex(Array.Empty<Ip2AsnRecord>()).Find(123u).Should().BeNull();
}
