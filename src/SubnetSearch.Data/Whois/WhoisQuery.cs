using System.Net.Sockets;

namespace SubnetSearch.Data;

internal static class WhoisQuery
{
    // WHOIS port per RFC 3912.
    private const int WhoisPort = 43;

    // Short connect timeout prevents hanging for the full OS TCP timeout (75-120s)
    // when a WHOIS server is unreachable. The caller's CancellationToken covers
    // the read phase once connected.
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);

    public static async Task<string> SendAsync(string server, string query, CancellationToken cancellationToken)
    {
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(ConnectTimeout);

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server, WhoisPort, connectCts.Token);

        await using var stream = tcp.GetStream();
        using var writer = new StreamWriter(stream);
        using var reader = new StreamReader(stream);
        await writer.WriteLineAsync(query.AsMemory(), cancellationToken);
        await writer.FlushAsync(cancellationToken);
        return await reader.ReadToEndAsync(cancellationToken);
    }
}
