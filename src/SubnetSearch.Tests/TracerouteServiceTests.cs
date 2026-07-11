using FluentAssertions;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Network;

namespace SubnetSearch.Tests;

public class TracerouteServiceTests
{
    private const string WindowsOutput = """
        Tracing route to example.com [93.184.216.34]
        over a maximum of 30 hops:

          1    <1 ms    <1 ms    <1 ms  192.168.1.1
          2     8 ms     9 ms     7 ms  10.0.0.1
          3     *        *        *     Request timed out.
        Trace complete.
        """;

    private const string LinuxOutput = """
        traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
         1  192.168.1.1  1.234 ms
         2  10.0.0.1  8.5 ms
         3  * * *
        """;

    [Fact]
    public void Parse_Windows_ExtractsHopsAndTimeout()
    {
        var hops = TracerouteService.Parse(WindowsOutput, isWindows: true);

        hops.Should().HaveCount(3);
        hops[0].Should().BeEquivalentTo(new { HopNumber = 1, IpAddress = "192.168.1.1" });
        hops[1].IpAddress.Should().Be("10.0.0.1");
        hops[1].LatencyMs.Should().Be(7);
        hops[2].HopNumber.Should().Be(3);
        hops[2].IpAddress.Should().BeNull("«* * *» → таймаут-хоп без IP");
    }

    [Fact]
    public void Parse_Linux_ExtractsHopsAndTimeout()
    {
        var hops = TracerouteService.Parse(LinuxOutput, isWindows: false);

        hops.Should().HaveCount(3);
        hops[0].IpAddress.Should().Be("192.168.1.1");
        hops[0].LatencyMs.Should().Be(1.234);
        hops[1].IpAddress.Should().Be("10.0.0.1");
        hops[2].IpAddress.Should().BeNull();
    }

    [Fact]
    public void Parse_HopsSortedByNumber()
    {
        var hops = TracerouteService.Parse(LinuxOutput, isWindows: false);
        hops.Select(h => h.HopNumber).Should().BeInAscendingOrder();
    }

    [Fact]
    public void Parse_EmptyOutput_ReturnsEmpty()
    {
        TracerouteService.Parse("", isWindows: true).Should().BeEmpty();
        TracerouteService.Parse("   ", isWindows: false).Should().BeEmpty();
    }

    [Fact]
    public void Parse_NoMatchingLines_ReturnsEmpty()
        => TracerouteService.Parse("garbage output with no hops", isWindows: false).Should().BeEmpty();
}
