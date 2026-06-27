using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace SubnetSearch.Network;

public static class NetworkInterfaceHelper
{
    // Имена интерфейсов, которые считаются VPN/тунелями/виртуальными.
    private static readonly string[] VirtualPrefixes =
    [
        "tun", "tap", "wg", "ppp", "vpn", "lo",
        "docker", "br-", "veth", "virbr", "dummy",
        "ipsec", "utun", "ztun"
    ];

    private static readonly string[] VirtualDescriptionKeywords =
    [
        "tap-windows", "virtual", "vpn", "loopback", "tunnel",
        "pseudo", "teredo", "isatap", "6to4"
    ];

    /// <summary>
    /// Возвращает имя физического сетевого интерфейса (Ethernet или Wi-Fi),
    /// исключая VPN/tunnel/virtual адаптеры.
    /// </summary>
    public static string? GetPhysicalInterfaceName()
        => GetPhysicalInterface()?.Name;

    /// <summary>
    /// Возвращает IPv4-адрес физического интерфейса для привязки сокетов.
    /// </summary>
    public static IPAddress? GetPhysicalIpAddress()
    {
        var iface = GetPhysicalInterface();
        if (iface == null) return null;
        return iface.GetIPProperties().UnicastAddresses
            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork
                     && !IPAddress.IsLoopback(a.Address))
            .Select(a => a.Address)
            .FirstOrDefault();
    }

    /// <summary>
    /// Создаёт HttpClient, привязанный к физическому интерфейсу и не использующий
    /// системный прокси — обходит VPN-маршрутизацию на уровне TCP-сокета.
    /// Возвращает null если физический интерфейс не определён (используй обычный HttpClient).
    /// </summary>
    public static HttpClient? CreateBypassVpnHttpClient(TimeSpan? timeout = null)
    {
        var localIp = GetPhysicalIpAddress();
        if (localIp == null) return null;

        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AutomaticDecompression = System.Net.DecompressionMethods.GZip
                                   | System.Net.DecompressionMethods.Deflate
                                   | System.Net.DecompressionMethods.Brotli,
            ConnectCallback = async (ctx, ct) =>
            {
                // Wrap with explicit 8s timeout — outer ct doesn't reliably abort
                // socket.ConnectAsync on Linux when remote IP silently drops SYN packets.
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(TimeSpan.FromSeconds(8));

                var addresses = await Dns.GetHostAddressesAsync(
                    ctx.DnsEndPoint.Host, AddressFamily.InterNetwork, connectCts.Token);
                if (addresses.Length == 0)
                    throw new SocketException((int)SocketError.HostNotFound);

                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true
                };
                socket.Bind(new IPEndPoint(localIp, 0));
                try
                {
                    await socket.ConnectAsync(addresses[0], ctx.DnsEndPoint.Port, connectCts.Token);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
        };

        var client = new HttpClient(handler);
        if (timeout.HasValue) client.Timeout = timeout.Value;
        return client;
    }

    private static NetworkInterface? GetPhysicalInterface()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .Where(n => n.NetworkInterfaceType is
                NetworkInterfaceType.Ethernet or
                NetworkInterfaceType.Wireless80211 or
                NetworkInterfaceType.GigabitEthernet or
                NetworkInterfaceType.FastEthernetFx or
                NetworkInterfaceType.FastEthernetT)
            .Where(n => !IsVirtual(n))
            .Where(n => n.GetIPProperties().UnicastAddresses
                .Any(a => a.Address.AddressFamily == AddressFamily.InterNetwork
                       && !IPAddress.IsLoopback(a.Address)))
            .OrderByDescending(n => n.Speed)
            .FirstOrDefault();
    }

    private static bool IsVirtual(NetworkInterface n)
    {
        var name = n.Name.ToLowerInvariant();
        if (VirtualPrefixes.Any(p => name.StartsWith(p, StringComparison.Ordinal)))
            return true;

        var desc = n.Description.ToLowerInvariant();
        if (VirtualDescriptionKeywords.Any(k => desc.Contains(k, StringComparison.Ordinal)))
            return true;

        return false;
    }
}
