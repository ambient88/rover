using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace SubnetSearch.Network;

public partial class TracerouteService : ITracerouteService
{
    // Linux: " 1  192.168.1.1  1.234 ms"  or " 3  * * *"
    [GeneratedRegex(@"^\s*(\d+)\s+(\S+)\s+([\d.]+)\s+ms", RegexOptions.Multiline)]
    private static partial Regex LinuxHopRegex();

    // Windows: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
    // Groups: 1=hop number, 2=3rd-probe latency (may start with <), 3=IP address
    [GeneratedRegex(@"^\s*(\d+)\s+[<\d*]+\s+ms\s+[<\d*]+\s+ms\s+(<?\d+)\s+ms\s+(\S+)", RegexOptions.Multiline)]
    private static partial Regex WindowsHopRegex();

    // Windows timeout hops: "  3     *        *        *     Request timed out."
    [GeneratedRegex(@"^\s*(\d+)\s+\*\s+\*\s+\*", RegexOptions.Multiline)]
    private static partial Regex WindowsTimeoutHopRegex();

    public async Task<IReadOnlyList<TracerouteHop>> TraceAsync(string host, CancellationToken cancellationToken = default)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                string output = await PingService.RunAsync("tracert", $"-d -w 2000 -h 30 {host}", cancellationToken);
                return Parse(output, isWindows: true);
            }
            catch { return []; }
        }

        string ifaceArg = NetworkInterfaceHelper.GetPhysicalInterfaceName() is { } iface
            ? $"-i {iface} " : "";

        // ICMP mode (-I) requires CAP_NET_RAW / root. Fall back to UDP (no privileges needed).
        var hops = await TryLinuxTraceAsync($"-I -w 2 -q 1 -m 30 -n {ifaceArg}{host}", cancellationToken);
        if (hops.Count > 0) return hops;
        return await TryLinuxTraceAsync($"-w 2 -q 1 -m 30 -n {ifaceArg}{host}", cancellationToken);
    }

    private static async Task<IReadOnlyList<TracerouteHop>> TryLinuxTraceAsync(string args, CancellationToken ct)
    {
        try
        {
            string output = await PingService.RunAsync("traceroute", args, ct);
            return Parse(output, isWindows: false);
        }
        catch (Exception e) when (e is not OperationCanceledException) { return []; }
    }

    internal static List<TracerouteHop> Parse(string output, bool isWindows)
    {
        var hops = new List<TracerouteHop>();
        if (string.IsNullOrWhiteSpace(output)) return hops;

        if (isWindows)
        {
            foreach (Match m in WindowsHopRegex().Matches(output))
            {
                string latStr = m.Groups[2].Value.TrimStart('<');
                double? lat = double.TryParse(latStr, System.Globalization.CultureInfo.InvariantCulture, out var l)
                    ? Math.Max(1.0, l) : (double?)null;
                hops.Add(new TracerouteHop(int.Parse(m.Groups[1].Value), m.Groups[3].Value, null, lat));
            }

            // Add timeout hops ("* * *") so TracerouteAnalyzer can detect hidden routes.
            // Without these, LikelyHiddenRoute is always false on Windows.
            foreach (Match m in WindowsTimeoutHopRegex().Matches(output))
            {
                int hopNum = int.Parse(m.Groups[1].Value);
                if (!hops.Any(h => h.HopNumber == hopNum))
                    hops.Add(new TracerouteHop(hopNum, null, null, null));
            }
        }
        else
        {
            foreach (Match m in LinuxHopRegex().Matches(output))
            {
                string ip = m.Groups[2].Value;
                double lat = double.Parse(m.Groups[3].Value, System.Globalization.CultureInfo.InvariantCulture);
                hops.Add(new TracerouteHop(int.Parse(m.Groups[1].Value), ip, null, lat));
            }

            // Add timeout hops ("* * *").
            var lines = output.Split('\n');
            foreach (var line in lines)
            {
                var m = Regex.Match(line.TrimStart(), @"^(\d+)\s+\*");
                if (!m.Success) continue;
                int num = int.Parse(m.Groups[1].Value);
                if (!hops.Any(h => h.HopNumber == num))
                    hops.Add(new TracerouteHop(num, null, null, null));
            }
        }

        return hops.OrderBy(h => h.HopNumber).ToList();
    }
}
