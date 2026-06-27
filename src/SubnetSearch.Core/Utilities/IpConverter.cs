using System.Net;
using System.Numerics;

namespace SubnetSearch.Core.Utilities;

public static class IpConverter
{
    public static uint IpToUint(string ip)
    {
        var bytes = IPAddress.Parse(ip).GetAddressBytes();
        if (bytes.Length != 4)
            throw new ArgumentException("Only IPv4 addresses are supported.");
        return (uint)(bytes[0] << 24) | (uint)(bytes[1] << 16) | (uint)(bytes[2] << 8) | bytes[3];
    }

    public static bool TryIpToUint(string ip, out uint value)
    {
        value = 0;
        if (!IPAddress.TryParse(ip, out var addr) || addr.GetAddressBytes().Length != 4)
            return false;
        var b = addr.GetAddressBytes();
        value = (uint)(b[0] << 24) | (uint)(b[1] << 16) | (uint)(b[2] << 8) | b[3];
        return true;
    }

    public static string UintToIp(uint ip) =>
        $"{ip >> 24}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}";

    public static bool TryParseCidr(string cidr, out uint start, out uint end)
    {
        start = end = 0;
        var parts = cidr.Trim().Split('/');
        if (parts.Length != 2) return false;
        if (!IPAddress.TryParse(parts[0], out var addr)) return false;
        if (!int.TryParse(parts[1], out int prefix) || prefix < 0 || prefix > 32) return false;
        var bytes = addr.GetAddressBytes();
        if (bytes.Length != 4) return false;
        uint ipVal = (uint)(bytes[0] << 24) | (uint)(bytes[1] << 16) | (uint)(bytes[2] << 8) | bytes[3];
        uint mask  = prefix == 0 ? 0u : ~((1u << (32 - prefix)) - 1);
        start = ipVal & mask;
        end   = start | ~mask;
        return true;
    }

    // Возвращает CIDR-нотацию если диапазон выровнен, иначе "start-end".
    public static string ToCidr(uint start, uint end)
    {
        ulong size = (ulong)end - start + 1;
        if (size > 0 && (size & (size - 1)) == 0 && ((ulong)start & (size - 1)) == 0)
        {
            int prefixLen = 32 - (int)Math.Log2(size);
            return $"{UintToIp(start)}/{prefixLen}";
        }
        return $"{UintToIp(start)}-{UintToIp(end)}";
    }
}
