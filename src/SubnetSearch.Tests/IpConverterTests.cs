using FluentAssertions;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Tests;

public class IpConverterTests
{
    [Theory]
    [InlineData("0.0.0.0",         0u)]
    [InlineData("1.0.0.0",         16777216u)]
    [InlineData("8.8.8.8",         134744072u)]
    [InlineData("192.168.1.1",     3232235777u)]
    [InlineData("255.255.255.255", 4294967295u)]
    public void IpToUint_ConvertsCorrectly(string ip, uint expected)
        => IpConverter.IpToUint(ip).Should().Be(expected);

    [Theory]
    [InlineData(0u,          "0.0.0.0")]
    [InlineData(134744072u,  "8.8.8.8")]
    [InlineData(3232235777u, "192.168.1.1")]
    public void UintToIp_ConvertsCorrectly(uint input, string expected)
        => IpConverter.UintToIp(input).Should().Be(expected);

    [Theory]
    [InlineData("8.8.8.0/24",   134744064u, 134744319u)]
    [InlineData("10.0.0.0/8",   167772160u, 184549375u)]
    [InlineData("1.2.3.4/32",   16909060u,  16909060u)]
    [InlineData("0.0.0.0/0",    0u,         4294967295u)]
    public void TryParseCidr_ParsesCorrectly(string cidr, uint expectedStart, uint expectedEnd)
    {
        IpConverter.TryParseCidr(cidr, out var start, out var end).Should().BeTrue();
        start.Should().Be(expectedStart);
        end.Should().Be(expectedEnd);
    }

    [Theory]
    [InlineData("not-a-cidr")]
    [InlineData("999.0.0.0/8")]
    [InlineData("1.2.3.4/33")]
    [InlineData("")]
    public void TryParseCidr_ReturnsFalseForInvalidInput(string cidr)
        => IpConverter.TryParseCidr(cidr, out _, out _).Should().BeFalse();

    [Theory]
    [InlineData(167772160u, 184549375u, "10.0.0.0/8")]
    [InlineData(134744064u, 134744319u, "8.8.8.0/24")]
    public void ToCidr_FormatsCorrectly(uint start, uint end, string expected)
        => IpConverter.ToCidr(start, end).Should().Be(expected);

    [Theory]
    [InlineData(1u, 3u, "0.0.0.1-0.0.0.3")]           // size is a power of two but start is unaligned
    [InlineData(0u, 2u, "0.0.0.0-0.0.0.2")]           // size 3 is not a power of two
    [InlineData(134744065u, 134744319u, "8.8.8.1-8.8.8.255")]
    public void ToCidr_FallsBackToRangeForUnalignedInput(uint start, uint end, string expected)
        => IpConverter.ToCidr(start, end).Should().Be(expected);
}
