using SubnetSearch.Core.Interfaces.Classification;
using System.Collections.Concurrent;
using System.Net.Sockets;

namespace SubnetSearch.Network;

public class PortScanner : IPortScanner
{
    private static readonly int[] DefaultPorts = [22, 80, 443, 3306, 8080, 8443];
    private const int TimeoutMs = 3000;

    public async Task<IReadOnlyList<int>> ScanAsync(
        string host,
        IEnumerable<int>? ports = null,
        CancellationToken cancellationToken = default)
    {
        int[] portsToScan = ports?.ToArray() ?? DefaultPorts;
        var open = new ConcurrentBag<int>();

        await Parallel.ForEachAsync(
            portsToScan,
            new ParallelOptions { MaxDegreeOfParallelism = 6, CancellationToken = cancellationToken },
            async (port, ct) =>
            {
                using var tcp = new TcpClient();
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    cts.CancelAfter(TimeoutMs);
                    await tcp.ConnectAsync(host, port, cts.Token);
                    open.Add(port);
                }
                catch { }
            });

        return open.OrderBy(p => p).ToList();
    }
}
