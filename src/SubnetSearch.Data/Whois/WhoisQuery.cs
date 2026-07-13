using System.Net.Sockets;
using System.Text;

namespace SubnetSearch.Data;

internal static class WhoisQuery
{
    // WHOIS port per RFC 3912.
    private const int WhoisPort = 43;

    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(3);
    internal const int MaxResponseChars = 1_048_576;

    // Raw WHOIS-over-TCP socket exchange — pure network I/O. The response parsing/size-limit logic
    // in ReadResponseAsync is unit-tested; this socket dance is integration-scope.
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    public static async Task<string> SendAsync(string server, string query, CancellationToken cancellationToken)
    {
        using var operationCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        operationCts.CancelAfter(OperationTimeout);

        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(operationCts.Token);
        connectCts.CancelAfter(ConnectTimeout);

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(server, WhoisPort, connectCts.Token);

        await using var stream = tcp.GetStream();
        using var writer = new StreamWriter(stream, leaveOpen: true);
        using var reader = new StreamReader(stream, leaveOpen: true);
        await writer.WriteLineAsync(query.AsMemory(), operationCts.Token);
        await writer.FlushAsync(operationCts.Token);
        return await ReadResponseAsync(reader, operationCts.Token);
    }

    internal static async Task<string> ReadResponseAsync(
        TextReader reader, CancellationToken cancellationToken)
    {
        var response = new StringBuilder(Math.Min(8192, MaxResponseChars));
        var buffer = new char[8192];

        while (true)
        {
            int read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (read == 0) return response.ToString();
            if (response.Length + read > MaxResponseChars)
                throw new InvalidDataException("WHOIS response exceeds the allowed size.");

            response.Append(buffer, 0, read);
        }
    }
}
