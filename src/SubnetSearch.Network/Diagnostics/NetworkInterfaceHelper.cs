using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Network;

// Physical-NIC enumeration + socket binding over the live OS network stack — integration-only.
[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
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

    private static readonly object _physicalLock = new();
    private static (string? Name, IPAddress? Ip)? _physical;

    private static (string? Name, IPAddress? Ip) GetPhysical(bool refresh = false)
    {
        lock (_physicalLock)
        {
            if (!refresh && _physical.HasValue)
                return _physical.Value;
            try
            {
                var iface = GetPhysicalInterface();
                var ip = iface?.GetIPProperties().UnicastAddresses
                    .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork
                             && !IPAddress.IsLoopback(a.Address))
                    .Select(a => a.Address)
                    .FirstOrDefault();
                return (_physical = (iface?.Name, ip)).Value;
            }
            catch
            {
                return (_physical = (null, null)).Value;
            }
        }
    }

    /// <summary>
    /// Возвращает имя физического сетевого интерфейса (Ethernet или Wi-Fi),
    /// исключая VPN/tunnel/virtual адаптеры.
    /// </summary>
    public static string? GetPhysicalInterfaceName() => GetPhysical().Name;

    /// <summary>
    /// Возвращает IPv4-адрес физического интерфейса для привязки сокетов.
    /// </summary>
    public static IPAddress? GetPhysicalIpAddress() => GetPhysical().Ip;

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
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectCallback = (ctx, ct) => ConnectPublicAsync(ctx, localIp, ct)
        };

        var client = new HttpClient(handler);
        if (timeout.HasValue) client.Timeout = timeout.Value;
        return client;
    }

    private static async ValueTask<Stream> ConnectPublicAsync(
        SocketsHttpConnectionContext context,
        IPAddress? localIp,
        CancellationToken cancellationToken)
    {
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        TimeSpan totalTimeout = TimeSpan.FromSeconds(8);
        connectCts.CancelAfter(totalTimeout);
        DateTimeOffset deadline = DateTimeOffset.UtcNow + totalTimeout;

        var addresses = await Dns.GetHostAddressesAsync(
            context.DnsEndPoint.Host, AddressFamily.InterNetwork, connectCts.Token);
        var publicAddresses = addresses
            .Where(IpListAnalyzer.IsPublicAddress)
            .Distinct()
            .ToArray();
        if (publicAddresses.Length == 0)
            throw new SocketException((int)SocketError.HostNotFound);

        IPAddress? bindIp = localIp;
        for (int i = 0; i < publicAddresses.Length; i++)
        {
            TimeSpan remaining = deadline - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero) break;

            int addressesLeft = publicAddresses.Length - i;
            TimeSpan attemptTimeout = TimeSpan.FromTicks(remaining.Ticks / addressesLeft);
            using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(connectCts.Token);
            attemptCts.CancelAfter(attemptTimeout);

            Socket? socket = null;
            try
            {
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true
                };
                if (bindIp != null) socket.Bind(new IPEndPoint(bindIp, 0));
                await socket.ConnectAsync(
                    publicAddresses[i], context.DnsEndPoint.Port, attemptCts.Token);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                socket?.Dispose();
                throw;
            }
            catch (SocketException ex) when (
                bindIp != null && ex.SocketErrorCode == SocketError.AddressNotAvailable)
            {
                socket?.Dispose();
                var refreshedIp = GetPhysical(refresh: true).Ip;
                if (refreshedIp != null && !refreshedIp.Equals(bindIp))
                {
                    bindIp = refreshedIp;
                    i--;
                }
            }
            catch
            {
                socket?.Dispose();
            }
        }

        throw new SocketException((int)SocketError.TimedOut);
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
