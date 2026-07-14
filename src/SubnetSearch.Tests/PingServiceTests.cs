using FluentAssertions;
using SubnetSearch.Network;

namespace SubnetSearch.Tests;

// Ping binds to the physical interface to bypass VPN routing.
// Windows uses -S with the source IP because some VPN clients fabricate sub-millisecond ICMP replies.
// Linux and macOS use -I with the interface name.
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

    // ping.exe output parsing must not depend on the operating system locale.
    // English-only patterns previously marked every host silent on localized Windows systems.

    private const string WindowsPingOutputEnglish = """
        Pinging 8.8.8.8 with 32 bytes of data:
        Reply from 8.8.8.8: bytes=32 time=25ms TTL=110

        Ping statistics for 8.8.8.8:
            Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
        Approximate round trip times in milli-seconds:
            Minimum = 24ms, Maximum = 27ms, Average = 25ms
        """;

    private const string WindowsPingOutputRussian = """
        Обмен пакетами с 8.8.8.8 по с 32 байтами данных:
        Ответ от 8.8.8.8: число байт=32 время=25мс TTL=110

        Статистика Ping для 8.8.8.8:
            Пакетов: отправлено = 4, получено = 3, потеряно = 1
            (25% потерь)
        Приблизительное время приема-передачи в мс:
            Минимальное = 24мсек, Максимальное = 27мсек, Среднее = 25мсек
        """;

    [Fact]
    public void Parse_WindowsEnglishOutput_ExtractsRttAndLoss() // English locale regression coverage.
    {
        var stats = PingService.Parse(WindowsPingOutputEnglish, isWindows: true);

        stats.Should().NotBeNull();
        stats!.MinMs.Should().Be(24);
        stats.MaxMs.Should().Be(27);
        stats.AvgMs.Should().Be(25);
        stats.PacketLoss.Should().Be(0);
    }

    [Fact]
    public void Parse_WindowsRussianOutput_ExtractsRttAndLoss() // Localized ping.exe output.
    {
        var stats = PingService.Parse(WindowsPingOutputRussian, isWindows: true);

        stats.Should().NotBeNull();
        stats!.MinMs.Should().Be(24);
        stats.MaxMs.Should().Be(27);
        stats.AvgMs.Should().Be(25);
        stats.PacketLoss.Should().Be(25);
    }

    [Fact]
    public void Parse_WindowsSilentHost_ReturnsNull() // A timeout response has no RTT line.
    {
        const string output = """
            Pinging 10.255.255.1 with 32 bytes of data:
            Request timed out.

            Ping statistics for 10.255.255.1:
                Packets: Sent = 1, Received = 0, Lost = 1 (100% loss),
            """;

        PingService.Parse(output, isWindows: true).Should().BeNull();
    }

    [Fact]
    public void Parse_LinuxOutput_ExtractsRttAndLoss() // Preserve Unix output parsing.
    {
        const string output = """
            PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
            64 bytes from 8.8.8.8: icmp_seq=1 ttl=110 time=24.1 ms

            --- 8.8.8.8 ping statistics ---
            3 packets transmitted, 3 received, 0% packet loss, time 2003ms
            rtt min/avg/max/mdev = 24.1/25.0/27.2/0.8 ms
            """;

        var stats = PingService.Parse(output, isWindows: false);

        stats.Should().NotBeNull();
        stats!.MinMs.Should().Be(24.1);
        stats.AvgMs.Should().Be(25.0);
        stats.MaxMs.Should().Be(27.2);
        stats.PacketLoss.Should().Be(0);
    }

    [Fact]
    public void Parse_EmptyOutput_ReturnsNull() // A failed process start can produce empty output.
    {
        PingService.Parse("", isWindows: true).Should().BeNull();
        PingService.Parse("", isWindows: false).Should().BeNull();
    }
}
