using SubnetSearch.Classification;
using SubnetSearch.Network;
using SubnetSearch.Cli.Config;

namespace SubnetSearch.Cli;

/// <summary>
/// Encapsulates all startup code: dataDir, data provisioning (Visible/Silent/None
/// via <see cref="DataProvisioner"/>), inline keys, and creating peeringDbHttp. Returns
/// a ready <see cref="CliContext"/> (or <c>null</c> on cancellation, Ctrl+C during download).
/// </summary>
public static class AppBootstrap
{
    public static async Task<CliContext?> InitializeAsync(string[] args, AppConfig appConfig, CancellationTokenSource cts)
    {
        // Set up shared services.
        string dataDir = DefaultDataPath.GetDefaultDataDirectory();

        // Provision data files.
        // Progress UI only on install / `rover update` / first run (no data yet).
        // A normal run with stale files does a quiet refresh (one line). All fresh means silence.
        var provisioner = new DataProvisioner(dataDir);
        bool isUpdate = args.Length > 0 && args[0].Equals("update", StringComparison.OrdinalIgnoreCase);
        await provisioner.ProvisionAsync(isUpdate, cts);

        if (cts.IsCancellationRequested)
        {
            // Cancellation during download: the router prints "Cancelled." on null and returns 130.
            return null;
        }

        // Parse arguments.
        bool forceWhois = args.Contains("--whois");

        // Inline keys override saved config for this run only (not persisted).
        var inlinePeeringDb = ArgsParser.GetArgValue(args, "--peeringdb-key");
        var inlineAbuseIpDb = ArgsParser.GetArgValue(args, "--abuseipdb-key");
        var inlineGreyNoise = ArgsParser.GetArgValue(args, "--greynoise-key");
        if (inlinePeeringDb != null) ConfigManager.ApplyInline(appConfig, "peeringdb", inlinePeeringDb);
        if (inlineAbuseIpDb != null) ConfigManager.ApplyInline(appConfig, "abuseipdb", inlineAbuseIpDb);
        if (inlineGreyNoise != null) ConfigManager.ApplyInline(appConfig, "greynoise",  inlineGreyNoise);

        // Initialize the PeeringDB client owned by CliContext.
        // Bypass VPN by binding to the physical network interface.
        // Falls back to default HttpClient if no physical interface is detected.
        var bypassClient = NetworkInterfaceHelper.CreateBypassVpnHttpClient()
            ?? new HttpClient();
        // The shared client carries no secret; the PeeringDB key travels per-request instead.
        var peeringDbHttp = ClassifierFactory.CreatePeeringDbHttpClient(bypassClient);

        return new CliContext(dataDir, peeringDbHttp, appConfig, forceWhois);
    }
}
