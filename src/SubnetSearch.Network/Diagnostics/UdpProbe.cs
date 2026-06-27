using System.Net;
using System.Net.Sockets;

namespace SubnetSearch.Network;

public static class UdpProbe
{
    // Sends a single UDP datagram and interprets the result:
    //   true  = ICMP "port unreachable" received → port is closed
    //   false = timeout / no ICMP reply          → port may be open (or filtered)
    //
    // For WireGuard (port 2408): a real WARP endpoint ignores invalid packets
    // (no reply), while a closed port returns ICMP unreachable.
    // Therefore: false == "possibly open", true == "definitely closed".
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
                // Got an unexpected response — port is not a standard WireGuard endpoint
                // but is not closed either.
                return false;
            }
            catch (OperationCanceledException)
            {
                // Timeout — no ICMP unreachable received → port is likely open.
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
            return false; // Unknown — assume not closed.
        }
    }
}
