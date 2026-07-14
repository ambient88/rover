using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace SubnetSearch.Network;

// Runs ICMP diagnostics through live sockets or the operating system ping command.
[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
public partial class PingService : IPingService
{
    // Linux/macOS: rtt min/avg/max/mdev = 1.2/3.4/5.6/0.8 ms
    [GeneratedRegex(@"rtt\s+\S+\s+=\s+([\d.]+)/([\d.]+)/([\d.]+)", RegexOptions.IgnoreCase)]
    private static partial Regex LinuxRttRegex();

    // Windows: Minimum = 1ms, Maximum = 5ms, Average = 3ms
    [GeneratedRegex(@"Minimum\s*=\s*(\d+)ms.*Maximum\s*=\s*(\d+)ms.*Average\s*=\s*(\d+)ms", RegexOptions.IgnoreCase)]
    private static partial Regex WindowsRttRegex();

    // Linux: X packets transmitted, Y received, Z% packet loss
    [GeneratedRegex(@"(\d+)%\s+packet\s+loss", RegexOptions.IgnoreCase)]
    private static partial Regex PacketLossRegex();

    // Windows: Lost = X (Z% loss)
    [GeneratedRegex(@"\((\d+)%\s+loss\)", RegexOptions.IgnoreCase)]
    private static partial Regex WindowsLossRegex();

    // WR-07: a language-independent fallback for a localized ping.exe. Localized builds
    // (for example Russian Windows) translate the min/max/avg labels, but the order
    // of min, max, avg is identical across locales, since it is one ping.exe format string.
    // The "number immediately followed by a unit letter" anchor does not match the packet
    // statistics line (localized "sent = 4, received = 4"), where no letters follow the number.
    [GeneratedRegex(@"=\s*(\d+)\s*\p{L}+[,;]\s*\p{L}+\s*=\s*(\d+)\s*\p{L}+[,;]\s*\p{L}+\s*=\s*(\d+)\s*\p{L}+")]
    private static partial Regex WindowsRttGenericRegex();

    // WR-07: the loss fallback is the only parenthesized percentage in ping.exe output,
    // which is the packet loss, e.g. "(25% loss)" or its localized equivalent.
    [GeneratedRegex(@"\((\d+)%[^)]*\)")]
    private static partial Regex WindowsLossGenericRegex();

    public async Task<PingStats?> PingAsync(string host, int count = 4, CancellationToken cancellationToken = default)
    {
        // Validate host before passing to the shell to prevent argument injection.
        if (!System.Net.IPAddress.TryParse(host, out _) &&
            Uri.CheckHostName(host) == UriHostNameType.Unknown)
            throw new ArgumentException($"Invalid host: '{host}'");

        string? iface  = NetworkInterfaceHelper.GetPhysicalInterfaceName();
        string? physIp = NetworkInterfaceHelper.GetPhysicalIpAddress()?.ToString();

        bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        string args = BuildPingArguments(host, count, isWindows, physIp, iface);

        string output = await RunAsync("ping", args, cancellationToken);
        return Parse(output, isWindows);
    }

    // Both branches bind ICMP to the physical interface, bypassing VPN routing:
    //   Windows: -S <source IP>. Without it some VPN clients short-circuit ICMP with
    //   fake replies under 1 ms with TTL 128 for any destination, confirmed on 2026-07-04.
    //   (8.8.8.8 via VPN route = 0ms/TTL 128; via -S physical = 25ms/TTL 110),
    //   which poisons all latency scoring in -r.
    //   Linux/macOS: -I <iface> (same bypass, pre-existing behavior).
    internal static string BuildPingArguments(
        string host, int count, bool isWindows,
        string? physicalSourceIp, string? physicalInterfaceName)
    {
        if (isWindows)
        {
            string srcArg = physicalSourceIp != null ? $"-S {physicalSourceIp} " : "";
            return $"-n {count} -w 1000 {srcArg}{host}";
        }
        string ifaceArg = physicalInterfaceName != null ? $"-I {physicalInterfaceName} " : "";
        return $"-c {count} -W 1 {ifaceArg}{host}";
    }

    // internal static plus an explicit isWindows: parsing is checked by offline tests on samples
    // of output from various locales (WR-07), mirroring BuildPingArguments.
    internal static PingStats? Parse(string output, bool isWindows)
    {
        if (string.IsNullOrWhiteSpace(output)) return null;

        int loss = 0;
        if (isWindows)
        {
            // WR-07: try the English regex first, then the language-independent fallback.
            // On localized Windows "Minimum = ..." never appears, and before the fix
            // every host was treated as silent (and cached as silent for 12 hours).
            var lossMatch = WindowsLossRegex().Match(output);
            if (!lossMatch.Success) lossMatch = WindowsLossGenericRegex().Match(output);
            if (lossMatch.Success) loss = int.Parse(lossMatch.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);

            var rttMatch = WindowsRttRegex().Match(output);
            if (!rttMatch.Success) rttMatch = WindowsRttGenericRegex().Match(output);
            if (!rttMatch.Success) return null;
            // Windows regex: Minimum=Groups[1], Maximum=Groups[2], Average=Groups[3]
            return new PingStats(
                double.Parse(rttMatch.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture),
                double.Parse(rttMatch.Groups[3].Value, System.Globalization.CultureInfo.InvariantCulture),
                double.Parse(rttMatch.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture),
                loss);
        }
        else
        {
            var lossMatch = PacketLossRegex().Match(output);
            if (lossMatch.Success) loss = int.Parse(lossMatch.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);

            var rttMatch = LinuxRttRegex().Match(output);
            if (!rttMatch.Success) return null;
            return new PingStats(
                double.Parse(rttMatch.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture),
                double.Parse(rttMatch.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture),
                double.Parse(rttMatch.Groups[3].Value, System.Globalization.CultureInfo.InvariantCulture),
                loss);
        }
    }

    internal static async Task<string> RunAsync(string cmd, string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(cmd, args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute        = false,
            CreateNoWindow         = true,
        };
        // WR-03: Process.Start returns null if the process could not be started,
        // the empty output is treated by the caller as "no data" (Parse returns null).
        using var process = Process.Start(psi);
        if (process == null) return string.Empty;
        try
        {
            // Read stdout and stderr concurrently because a full stderr buffer can block the process.
            // the OS pipe buffer, the child process blocks and WaitForExitAsync hangs forever.
            var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
            var stderrTask = process.StandardError.ReadToEndAsync(ct);
            string output = await stdoutTask;
            await stderrTask;
            await process.WaitForExitAsync(ct);
            return output;
        }
        catch (OperationCanceledException)
        {
            // WR-03: the process may already have exited on its own, so Kill would throw
            // InvalidOperationException and mask the original cancellation.
            try { process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            throw;
        }
    }
}
