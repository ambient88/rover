using FluentAssertions;
using SubnetSearch.Network;

namespace SubnetSearch.Tests;

public class ProviderScannerHelpersTests
{
    [Theory]
    [InlineData("1.2.3.0/24", 256)]
    [InlineData("10.0.0.0/8",  16777216)]
    [InlineData("1.2.3.4/32",  1)]
    public void CalcIpCount_ComputesHostCount(string prefix, int expected)
        => ProviderScanner.CalcIpCount(prefix).Should().Be(expected);

    [Theory]
    [InlineData("1.2.3.4")] 
    [InlineData("1.2.3.0/33")] 
    [InlineData("bad/prefix")] 
    public void CalcIpCount_InvalidPrefix_ReturnsZero(string prefix)
        => ProviderScanner.CalcIpCount(prefix).Should().Be(0);

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
