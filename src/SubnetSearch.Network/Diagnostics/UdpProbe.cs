using System.Net;
using System.Net.Sockets;

namespace SubnetSearch.Network;

// Raw UDP socket probe with live network I/O. This is covered by integration tests only.
[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
public static class UdpProbe
{
    // Sends a single UDP datagram and interprets the result:
    // true means an ICMP "port unreachable" response confirmed a closed port.
    // false means a timeout left the port open or filtered.
    //
    // For WireGuard (port 2408): a real WARP endpoint ignores invalid packets
    // (no reply), while a closed port returns ICMP unreachable.
    // False means the port may be open, while true confirms it is closed.
    public static async Task<bool> IsClosedAsync(
        string host, int port, int timeoutMs = 2000, CancellationToken ct = default)
    {
        try
        {
            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = timeoutMs;

            // Connect first so ICMP errors are routed back to this socket.
            udp.Connect(host, port);
            await udp.SendAsync(new ReadOnlyMemory<byte>([0x00]), ct);

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeoutMs);
                await udp.ReceiveAsync(cts.Token);
                // An unexpected response means the port is not a standard WireGuard endpoint.
                // but is not closed either.
                return false;
            }
            catch (OperationCanceledException)
            {
                // A timeout without an ICMP unreachable response usually means the port is open.
                return false;
            }
            catch (SocketException ex) when (
                ex.SocketErrorCode is SocketError.ConnectionReset      // Windows ICMP unreachable
                                   or SocketError.ConnectionRefused    // Linux ICMP unreachable
                                   or SocketError.HostUnreachable)
            {
                return true; // Definitely closed.
            }
        }
        catch
        {
            return false; // Treat an unknown result as not closed.
        }
    }
}
