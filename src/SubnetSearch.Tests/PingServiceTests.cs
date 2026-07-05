using FluentAssertions;
using SubnetSearch.Network;

namespace SubnetSearch.Tests;

// Аргументы ping должны привязывать источник к физическому интерфейсу, минуя VPN:
// Windows: -S <src IP> (без него VPN-клиент фабрикует ICMP-ответы <1ms TTL=128 на ЛЮБОЙ
// адрес — доказано 2026-07-04: 8.8.8.8 через VPN = 0ms/TTL 128, через -S = 25ms/TTL 110).
// Linux/macOS: -I <iface> (уже было).
public class PingServiceTests
{
    [Fact]
    public void WindowsArgs_WithPhysicalIp_BindSourceViaS()
    {
        var args = PingService.BuildPingArguments(
            host: "95.216.0.1", count: 3, isWindows: true,
            physicalSourceIp: "192.168.1.81", physicalInterfaceName: "Ethernet");

        args.Should().Be("-n 3 -w 1000 -S 192.168.1.81 95.216.0.1");
    }

    [Fact]
    public void WindowsArgs_WithoutPhysicalIp_NoSourceBinding()
    {
        var args = PingService.BuildPingArguments(
            host: "8.8.8.8", count: 4, isWindows: true,
            physicalSourceIp: null, physicalInterfaceName: null);

        args.Should().Be("-n 4 -w 1000 8.8.8.8");
    }

    [Fact]
    public void UnixArgs_WithInterface_BindViaI()
    {
        var args = PingService.BuildPingArguments(
            host: "95.216.0.1", count: 3, isWindows: false,
            physicalSourceIp: "192.168.1.81", physicalInterfaceName: "eth0");

        args.Should().Be("-c 3 -W 1 -I eth0 95.216.0.1");
    }

    [Fact]
    public void UnixArgs_WithoutInterface_NoBinding()
    {
        var args = PingService.BuildPingArguments(
            host: "8.8.8.8", count: 4, isWindows: false,
            physicalSourceIp: null, physicalInterfaceName: null);

        args.Should().Be("-c 4 -W 1 8.8.8.8");
    }
}
