using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Network;

internal static class Ipv4RangeMath
{
    public static long CountAddresses(string value)
        => TryParseRange(value, out uint start, out uint end)
            ? (long)((ulong)end - start + 1)
            : 0;

    public static long CountUniqueAddresses(IEnumerable<string> values)
    {
        var ranges = values
            .Select(value => TryParseRange(value, out uint start, out uint end)
                ? (Valid: true, Start: start, End: end)
                : default)
            .Where(range => range.Valid)
            .OrderBy(range => range.Start)
            .ThenBy(range => range.End)
            .ToList();

        if (ranges.Count == 0) return 0;

        ulong total = 0;
        uint currentStart = ranges[0].Start;
        uint currentEnd = ranges[0].End;

        foreach (var range in ranges.Skip(1))
        {
            if ((ulong)range.Start <= (ulong)currentEnd + 1)
            {
                if (range.End > currentEnd) currentEnd = range.End;
                continue;
            }

            total += (ulong)currentEnd - currentStart + 1;
            currentStart = range.Start;
            currentEnd = range.End;
        }

        total += (ulong)currentEnd - currentStart + 1;
        return checked((long)total);
    }

    private static bool TryParseRange(string value, out uint start, out uint end)
    {
        if (IpConverter.TryParseCidr(value, out start, out end)) return true;

        int separator = value.IndexOf('-');
        if (separator > 0 &&
            IpConverter.TryIpToUint(value[..separator], out start) &&
            IpConverter.TryIpToUint(value[(separator + 1)..], out end) &&
            end >= start)
        {
            return true;
        }

        start = 0;
        end = 0;
        return false;
    }
}
