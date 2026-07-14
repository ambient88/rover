using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using SubnetSearch.Network;

namespace SubnetSearch.Tests;

// PortScanner uses real TCP connections against a local listener on an ephemeral port.
public class PortScannerTests
{
    // Start a TCP listener on an available loopback port and return it with the port number.
    private static (int Port, TcpListener Listener) StartListener()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        return (port, listener);
    }

    [Fact]
    public async Task Scan_OpenPort_IsReported()
    {
        var (port, listener) = StartListener();
        try
        {
            var open = await new PortScanner().ScanAsync("127.0.0.1", new[] { port });

            open.Should().Contain(port);
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task Scan_ClosedPort_NotReported()
    {
        // Stop a new listener immediately to obtain an available closed port.
        var (port, listener) = StartListener();
        listener.Stop();

        var open = await new PortScanner().ScanAsync("127.0.0.1", new[] { port });

        open.Should().NotContain(port);
    }

    [Fact]
    public async Task Scan_NullPorts_UsesDefaultWellKnownSet()
    {
        int[] wellKnown = [22, 80, 443, 3306, 8080, 8443];

        // Loopback connects fail fast on closed ports; open results depend on the
        // machine, so only the port universe is asserted, not exact membership.
        var open = await new PortScanner().ScanAsync("127.0.0.1", ports: null);

        open.Should().BeSubsetOf(wellKnown);
    }

    [Fact]
    public async Task Scan_MixedPorts_ReturnsOnlyOpenSorted()
    {
        var (openPort, listener) = StartListener();
        var (closedPort, closedListener) = StartListener();
        closedListener.Stop(); // This port is closed.
        try
        {
            var result = await new PortScanner().ScanAsync("127.0.0.1", new[] { closedPort, openPort });

            result.Should().Contain(openPort);
            result.Should().NotContain(closedPort);
            result.Should().BeInAscendingOrder();
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task Scan_Cancellation_Throws()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await new PortScanner().Invoking(s => s.ScanAsync("127.0.0.1", new[] { 80, 443 }, cts.Token))
            .Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task Scan_EmptyPortList_ReturnsEmpty()
    {
        var open = await new PortScanner().ScanAsync("127.0.0.1", Array.Empty<int>());

        open.Should().BeEmpty();
    }
}
