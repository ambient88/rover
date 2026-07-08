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

    // Физический интерфейс не меняется за время жизни CLI-процесса, а перечисление
    // адаптеров стоит десятки миллисекунд — каждый PingAsync дёргал его дважды,
    // что при сотнях пингов в -r складывалось в секунды. Кэшируем один раз.
    private static readonly Lazy<(string? Name, IPAddress? Ip)> _physical = new(() =>
    {
        // WR-10: Lazy в режиме по умолчанию кэширует исключение фабрики на всю жизнь
        // процесса — транзиентный сбой перечисления адаптеров превращался бы в
        // постоянный. Нет NIC-инфо → ping без привязки, bypass-клиент возвращает null.
        try
        {
            var iface = GetPhysicalInterface();
            var ip = iface?.GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork
                         && !IPAddress.IsLoopback(a.Address))
                .Select(a => a.Address)
                .FirstOrDefault();
            return (iface?.Name, ip);
        }
        catch { return (null, null); }
    });

    /// <summary>
    /// Возвращает имя физического сетевого интерфейса (Ethernet или Wi-Fi),
    /// исключая VPN/tunnel/virtual адаптеры.
    /// </summary>
    public static string? GetPhysicalInterfaceName() => _physical.Value.Name;

    /// <summary>
    /// Возвращает IPv4-адрес физического интерфейса для привязки сокетов.
    /// </summary>
    public static IPAddress? GetPhysicalIpAddress() => _physical.Value.Ip;

    /// <summary>
    /// Создаёт HttpClient, привязанный к физическому интерфейсу и не использующий
    /// системный прокси — обходит VPN-маршрутизацию на уровне TCP-сокета.
    /// Возвращает null если физический интерфейс не определён (используй обычный HttpClient).
    /// </summary>
    public static HttpClient? CreateBypassVpnHttpClient(TimeSpan? timeout = null)
    {
        var localIp = GetPhysicalIpAddress();
        if (localIp == null) return null;

        // AutomaticDecompression intentionally omitted: binary .gz archives
        // must be saved byte-for-byte intact; transparent decompression corrupts them.
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
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
