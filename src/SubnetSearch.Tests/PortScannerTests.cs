using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using SubnetSearch.Network;

namespace SubnetSearch.Tests;

// PortScanner проверяет реальные TCP-подключения. Тесты детерминированы: слушатель
// поднимается на localhost на эфемерном порту, никакой внешней сети.
public class PortScannerTests
{
    // Поднимает TCP-слушателя на свободном порту loopback; возвращает порт и disposable.
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
    public async Task Scan_ClosedPort_NotReported() // краевой случай: закрытый порт
    {
        // Поднимаем и сразу останавливаем слушателя — порт освобождён (почти наверняка закрыт).
        var (port, listener) = StartListener();
        listener.Stop();

        var open = await new PortScanner().ScanAsync("127.0.0.1", new[] { port });

        open.Should().NotContain(port);
    }

    [Fact]
    public async Task Scan_MixedPorts_ReturnsOnlyOpenSorted()
    {
        var (openPort, listener) = StartListener();
        var (closedPort, closedListener) = StartListener();
        closedListener.Stop(); // этот порт закрыт
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
    public async Task Scan_Cancellation_Throws() // краевой случай: отмена скана
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await new PortScanner().Invoking(s => s.ScanAsync("127.0.0.1", new[] { 80, 443 }, cts.Token))
            .Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task Scan_EmptyPortList_ReturnsEmpty() // краевой случай: пустой список портов
    {
        var open = await new PortScanner().ScanAsync("127.0.0.1", Array.Empty<int>());

        open.Should().BeEmpty();
    }
}
