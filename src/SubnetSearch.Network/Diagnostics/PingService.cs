using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace SubnetSearch.Network;

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

    // WR-07: языконезависимый фолбэк для локализованного ping.exe (русская Windows:
    // «Минимальное = 24мсек, Максимальное = 27мсек, Среднее = 25мсек»). Порядок
    // min, max, avg одинаков на всех локалях — это один формат-стринг ping.exe.
    // Якорь «число сразу с буквенным суффиксом единицы» не матчит строку статистики
    // пакетов («отправлено = 4, получено = 4») — там после числа нет букв.
    [GeneratedRegex(@"=\s*(\d+)\s*\p{L}+[,;]\s*\p{L}+\s*=\s*(\d+)\s*\p{L}+[,;]\s*\p{L}+\s*=\s*(\d+)\s*\p{L}+")]
    private static partial Regex WindowsRttGenericRegex();

    // WR-07: фолбэк потерь — единственный процент в скобках в выводе ping.exe
    // это packet loss: «(25% loss)» / «(25% потерь)».
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
    //   fake replies (<1ms, TTL=128) for ANY destination — proven 2026-07-04
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

    // internal static + явный isWindows: разбор проверяется офлайн-тестами на образцах
    // вывода разных локалей (WR-07), по аналогии с BuildPingArguments.
    internal static PingStats? Parse(string output, bool isWindows)
    {
        if (string.IsNullOrWhiteSpace(output)) return null;

        int loss = 0;
        if (isWindows)
        {
            // WR-07: сначала английский регекс, затем языконезависимый фолбэк —
            // на локализованной Windows «Minimum = ...» не встречается, и до фикса
            // каждый хост считался silent (и кэшировался как silent на 12 часов).
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

    public async Task<PingStats?> PingViaTracerouteAsync(
        string host, uint targetAsn, IIpRangeIndex ipIndex, CancellationToken ct = default)
    {
        var tracer = new TracerouteService();
        IReadOnlyList<TracerouteHop> hops;
        try { hops = await tracer.TraceAsync(host, ct); }
        catch (Exception e) when (e is not OperationCanceledException) { return null; }
        if (hops.Count == 0) return null;

        double? targetMs  = null;
        double? lastKnownMs = null;
        foreach (var hop in hops)
        {
            if (hop.LatencyMs.HasValue) lastKnownMs = hop.LatencyMs;
            if (hop.IpAddress == null) continue;
            if (!IpConverter.TryIpToUint(hop.IpAddress, out uint ipUint)) continue;
            var record = ipIndex.Find(ipUint);
            if (record?.Asn == targetAsn) { targetMs = hop.LatencyMs ?? lastKnownMs; break; }
        }
        if (targetMs == null) return null;
        return new PingStats(targetMs.Value, targetMs.Value, targetMs.Value, PacketLoss: 0, IsTcp: false);
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
        // WR-03: Process.Start возвращает null, если процесс не удалось запустить —
        // пустой вывод трактуется вызывающим как «нет данных» (Parse вернёт null).
        using var process = Process.Start(psi);
        if (process == null) return string.Empty;
        try
        {
            // Read stdout and stderr concurrently — if only stdout is read and stderr fills
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
            // WR-03: процесс мог уже завершиться сам — Kill бросил бы
            // InvalidOperationException и замаскировал бы исходную отмену.
            try { process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            throw;
        }
    }
}
