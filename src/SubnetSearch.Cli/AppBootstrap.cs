using SubnetSearch.Classification;
using SubnetSearch.Network;
using SubnetSearch.Cli.Config;

namespace SubnetSearch.Cli;

/// <summary>
/// Инкапсулирует весь startup-код запуска: dataDir, провижининг данных (Visible/Silent/None
/// через <see cref="DataProvisioner"/>), inline-ключи и создание peeringDbHttp. Возвращает
/// готовый <see cref="CliContext"/> (или <c>null</c> при отмене — Ctrl+C во время загрузки).
/// </summary>
public static class AppBootstrap
{
    public static async Task<CliContext?> InitializeAsync(string[] args, AppConfig appConfig, CancellationTokenSource cts)
    {
        // ================== SETUP ==================
        string dataDir = DefaultDataPath.GetDefaultDataDirectory();

        // ================== DATA FILES ==================
        // Визуал прогресса — только при установке / `rover update` / первом запуске (нет данных).
        // Обычный запуск с устаревшими файлами — тихий рефреш (одна строка). Всё свежее — тишина.
        var provisioner = new DataProvisioner(dataDir);
        bool isUpdate = args.Length > 0 && args[0].Equals("update", StringComparison.OrdinalIgnoreCase);
        await provisioner.ProvisionAsync(isUpdate, cts);

        if (cts.IsCancellationRequested)
        {
            // Отмена во время загрузки: router по null печатает «Cancelled.» и возвращает 130.
            return null;
        }

        // ================== ARGUMENTS ==================
        bool forceWhois = args.Contains("--whois");

        // Inline keys override saved config for this run only (not persisted).
        var inlinePeeringDb = ArgsParser.GetArgValue(args, "--peeringdb-key");
        var inlineAbuseIpDb = ArgsParser.GetArgValue(args, "--abuseipdb-key");
        var inlineGreyNoise = ArgsParser.GetArgValue(args, "--greynoise-key");
        if (inlinePeeringDb != null) ConfigManager.ApplyInline(appConfig, "peeringdb", inlinePeeringDb);
        if (inlineAbuseIpDb != null) ConfigManager.ApplyInline(appConfig, "abuseipdb", inlineAbuseIpDb);
        if (inlineGreyNoise != null) ConfigManager.ApplyInline(appConfig, "greynoise",  inlineGreyNoise);

        // ================== INIT: PeeringDB client (owned by router via CliContext) ==================
        // Bypass VPN by binding to the physical network interface.
        // Falls back to default HttpClient if no physical interface is detected.
        var bypassClient = NetworkInterfaceHelper.CreateBypassVpnHttpClient();
        // The shared client carries no secret; the PeeringDB key travels per-request instead.
        var peeringDbHttp = ClassifierFactory.CreatePeeringDbHttpClient(bypassClient);

        return new CliContext(dataDir, peeringDbHttp, appConfig, forceWhois);
    }
}
