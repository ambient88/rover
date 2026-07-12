using FluentAssertions;
using SubnetSearch.Network;

namespace SubnetSearch.Tests;

public class ProviderScannerHelpersTests
{
    [Theory]
    [InlineData("1.2.3.0/24", 256L)]
    [InlineData("10.0.0.0/8",  16777216L)]
    [InlineData("1.2.3.4/32",  1L)]
    // Wide prefixes overflow a 32-bit int: /1 = 2^31, /0 = 2^32 (F20).
    [InlineData("1.2.3.0/1",   2147483648L)]
    [InlineData("0.0.0.0/0",   4294967296L)]
    public void CalcIpCount_ComputesHostCount(string prefix, long expected)
        => ProviderScanner.CalcIpCount(prefix).Should().Be(expected);

    [Theory]
    [InlineData("1.2.3.4")]
    [InlineData("1.2.3.0/33")]
    [InlineData("1.2.3.0/-1")]
    [InlineData("bad/prefix")]
    public void CalcIpCount_InvalidPrefix_ReturnsZero(string prefix)
        => ProviderScanner.CalcIpCount(prefix).Should().Be(0L);

    [Fact]
    public void ParseHolder_SplitsHandleAndOrg()
        => ProviderScanner.ParseHolder("SENKO-AS Senko Digital LLC")
            .Should().Be(("SENKO-AS", "Senko Digital LLC"));

    [Fact]
    public void ParseHolder_NoSpace_HandleOnly()
        => ProviderScanner.ParseHolder("SOLO-AS").Should().Be(("SOLO-AS", (string?)null));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ParseHolder_EmptyOrNull_ReturnsNulls(string? holder)
        => ProviderScanner.ParseHolder(holder).Should().Be(((string?)null, (string?)null));
}
