using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Tests;

// IpRangeIndex: бинарный поиск ASN-записи по числовому IP в отсортированном массиве диапазонов.
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
        Rec("1.0.0.0",  "1.0.0.255",  13335),   // намеренно не по порядку — индекс сам сортирует
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
    [InlineData("1.0.0.0")]     // нижняя граница
    [InlineData("1.0.0.255")]   // верхняя граница
    public void Find_BoundaryAddresses_AreInclusive(string ip)
    {
        var rec = Index().Find(IpConverter.IpToUint(ip));
        rec.HasValue.Should().BeTrue();
        rec!.Value.Asn.Should().Be(13335u);
    }

    [Theory]
    [InlineData("9.9.9.9")]     // между диапазонами
    [InlineData("255.255.255.255")]
    public void Find_IpOutsideAnyRange_ReturnsNull(string ip)
        => Index().Find(IpConverter.IpToUint(ip)).Should().BeNull();

    [Fact]
    public void Find_EmptyIndex_ReturnsNull() // краевой случай: пустой индекс
        => new IpRangeIndex(Array.Empty<Ip2AsnRecord>()).Find(123u).Should().BeNull();
}
