using SubnetSearch.Classification;
using SubnetSearch.Network;
using SubnetSearch.Cli.Config;
using SubnetSearch.Core.Models.Data;

namespace SubnetSearch.Cli;

/// <summary>
/// Инкапсулирует весь startup-код запуска: dataDir, download-конвейер (system route
/// + bypass-VPN retry), inline-ключи и создание peeringDbHttp. Возвращает готовый
/// <see cref="CliContext"/> (или <c>null</c> при отмене — Ctrl+C во время загрузки).
/// </summary>
public static class AppBootstrap
{
    public static async Task<CliContext?> InitializeAsync(string[] args, AppConfig appConfig, CancellationTokenSource cts)
    {
        // ================== SETUP ==================
        string dataDir = DefaultDataPath.GetDefaultDataDirectory();

        var downloadOptions = new DownloadOptions
        {
            MaxRetries            = 3,
            RetryDelayMilliseconds = 2000,
            TimeoutSeconds        = 600,
            UseResume             = true,
            PartialDownloadsDir   = dataDir  // persistent cross-run resume
        };

        // Downloads use the system route first (VPN included): some ISPs throttle direct
        // traffic to the data hosts down to zero while the VPN path works fine.
        // Files that fail here are retried over the physical interface (bypass VPN) below —
        // that covers the opposite case where the VPN path is the blocked one.
        using var downloadHttp = DownloadManagerFactory.CreateHttpClient(downloadOptions);

        var downloader      = DownloadManagerFactory.CreateDownloader(downloadHttp);
        var storage         = DownloadManagerFactory.CreateStorage(dataDir);
        var files           = DownloadManagerFactory.GetDefaultFiles();
        var metaStore       = new SubnetSearch.Data.FileMetadataStore(dataDir);
        var downloadManager = new DownloadManager(downloader, storage, files, metaStore);

        // ================== DATA FILES ==================
        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new DownloadedColumn(),
                new TransferSpeedColumn(),
                new RemainingTimeColumn()
            })
            .StartAsync(async ctx =>
            {
                var spectreTaskMap = files.ToDictionary(
                    f => f.FileName,
                    f => ctx.AddTask($"[green]{Markup.Escape(f.FileName)}[/]", maxValue: 1, autoStart: false));

                Func<FileDescriptor, IProgress<DownloadProgress>?> progressFactory = file =>
                {
                    var t = spectreTaskMap[file.FileName];
                    t.StartTask();
                    return new Progress<DownloadProgress>(p =>
                    {
                        if (p.TotalBytes.HasValue && t.MaxValue != p.TotalBytes.Value)
                            t.MaxValue = p.TotalBytes.Value;
                        t.Value = p.BytesDownloaded;
                    });
                };

                var results = await downloadManager.DownloadAllDetailedAsync(
                    downloadOptions,
                    progressFactory,
                    maxDegreeOfParallelism: 3,
                    cancellationToken: cts.Token);

                // Retry failures over the physical interface (bypass VPN) — covers the case
                // where the VPN path is the blocked one for a particular host.
                if (results.Any(r => !r.Success) && !cts.IsCancellationRequested)
                {
                    var bypass = NetworkInterfaceHelper.CreateBypassVpnHttpClient(
                        TimeSpan.FromSeconds(downloadOptions.TimeoutSeconds));
                    if (bypass != null)
                    {
                        using (bypass)
                        {
                            bypass.DefaultRequestHeaders.UserAgent.ParseAdd("SubnetSearch/1.0");
                            var retryManager = new DownloadManager(
                                DownloadManagerFactory.CreateDownloader(bypass), storage, files, metaStore);
                            var retryResults = await retryManager.DownloadAllDetailedAsync(
                                downloadOptions,
                                progressFactory,
                                maxDegreeOfParallelism: 3,
                                cancellationToken: cts.Token);
                            // Files that succeeded on the first pass keep their result;
                            // failed ones take the outcome of the bypass retry.
                            results = results
                                .Select(r => r.Success ? r : retryResults.First(x => x.FileName == r.FileName))
                                .ToList();
                        }
                    }
                }

                foreach (var r in results)
                {
                    var t = spectreTaskMap[r.FileName];
                    if (r.Skipped)
                    {
                        t.Description = $"[gray]{Markup.Escape(r.FileName)} (up to date)[/]";
                        t.Value = 100;
                    }
                    else if (r.NotModified)
                    {
                        t.Description = $"[gray]{Markup.Escape(r.FileName)} (not modified)[/]";
                        t.Value = 100;
                    }
                    else if (r.Stale)
                    {
                        t.Description = $"[yellow]{Markup.Escape(r.FileName)} (stale — update failed: {Markup.Escape(r.ErrorMessage ?? "")})[/]";
                        t.Value = 100;
                    }
                    else if (!r.Success)
                    {
                        t.Description = $"[red]{Markup.Escape(r.FileName)} (error: {Markup.Escape(r.ErrorMessage ?? "")})[/]";
                    }
                    else
                    {
                        t.Description = $"[green]{Markup.Escape(r.FileName)} (updated)[/]";
                        t.Value = t.MaxValue;
                    }
                    t.StopTask();
                }
            });


        Console.WriteLine("\nDownload complete.\n");

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
        var peeringDbHttp = ClassifierFactory.CreatePeeringDbHttpClient(bypassClient, appConfig.PeeringDbKey);

        return new CliContext(dataDir, peeringDbHttp, appConfig, forceWhois);
    }
}
