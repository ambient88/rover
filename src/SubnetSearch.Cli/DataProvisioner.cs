using SubnetSearch.Network;
using SubnetSearch.Core.Models.Data;

namespace SubnetSearch.Cli;

/// <summary>
/// Single entry point for data-file provisioning. It picks a mode
/// (<see cref="ProvisioningStatus.Decide"/>) and runs it:
///   Visible: install / <c>rover update</c> / first run, with the full Spectre progress table;
///   Silent restores the required IP-to-ASN file without the full progress view.
///   None uses valid local files immediately, even when their refresh TTL has elapsed.
/// The download core (DownloadManager plus a bypass-VPN retry) is shared by Visible and Silent.
/// </summary>
public sealed class DataProvisioner
{
    private static readonly HashSet<string> ForegroundRequiredFiles =
        new(StringComparer.OrdinalIgnoreCase) { "ip2asn-v4.tsv.gz" };

    private readonly IReadOnlyList<FileDescriptor> _files;
    private readonly SubnetSearch.Core.Interfaces.Data.IFileStorage _storage;
    private readonly FileMetadataStore _meta;
    private readonly DownloadOptions _options;
    private readonly string _dataDir;

    public DataProvisioner(string dataDir)
    {
        _dataDir = dataDir;
        _files   = DownloadManagerFactory.GetDefaultFiles();
        _storage = DownloadManagerFactory.CreateStorage(dataDir);
        _meta    = new FileMetadataStore(dataDir);
        _options = new DownloadOptions
        {
            MaxRetries             = 3,
            RetryDelayMilliseconds = 2000,
            TimeoutSeconds         = 600,
            UseResume              = true,
            PartialDownloadsDir    = dataDir  // persistent cross-run resume
        };
    }

    /// <summary>Picks a mode and runs it. Does nothing in None mode.</summary>
    public async Task ProvisionAsync(bool isUpdateCommand, CancellationTokenSource cts)
    {
        var status = new ProvisioningStatus(_storage, _files, _meta);
        var mode   = ProvisioningStatus.Decide(
            isUpdateCommand,
            status.AnyFileValid(),
            status.AnyFileInvalid());

        switch (mode)
        {
            case ProvisioningMode.Visible: await RunVisibleAsync(cts, isUpdateCommand); break;
            case ProvisioningMode.Silent:  await RunSilentAsync(cts);  break;
            // None: intentionally do nothing.
        }
    }

    // Visible provisioning shows the full progress table for installation, updates, and first run.
    private async Task RunVisibleAsync(CancellationTokenSource cts, bool force)
    {
        using var http = DownloadManagerFactory.CreateHttpClient(_options);
        var manager = new DownloadManager(
            DownloadManagerFactory.CreateDownloader(http), _storage, _files, _meta);

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
                var spectreTaskMap = _files.ToDictionary(
                    f => f.FileName,
                    f => ctx.AddTask($"[green]{Markup.Escape(f.FileName)}[/]", maxValue: 1, autoStart: false));

                Func<FileDescriptor, IProgress<DownloadProgress>?> progressFactory = file =>
                {
                    var t = spectreTaskMap[file.FileName];
                    t.StartTask();
                    return new Progress<DownloadProgress>(p =>
                    {
                        if (p.TotalBytes is > 0)
                        {
                            if (t.MaxValue != p.TotalBytes.Value) t.MaxValue = p.TotalBytes.Value;
                        }
                        else
                        {
                            // No Content-Length: keep the ceiling ahead of the byte count so the bar
                            // never snaps to 100% before the transfer actually finishes.
                            t.MaxValue = Math.Max(t.MaxValue, p.BytesDownloaded + 1);
                        }
                        t.Value = p.BytesDownloaded;
                    });
                };

                var results = await ExecuteWithBypassRetryAsync(
                    manager, _files, progressFactory, force, cts);

                foreach (var r in results)
                {
                    var t = spectreTaskMap[r.FileName];
                    // Skipped files never ran the download callback, so their task stayed unstarted
                    // and stuck at 0%. Start it and fill the bar to the file's real on-disk size so
                    // every terminal state shows a complete bar with the correct byte total.
                    if (!t.IsStarted) t.StartTask();
                    long size = FileSizeOnDisk(r.FileName);
                    if (size > 0) t.MaxValue = size;

                    if (r.Skipped)
                    {
                        t.Description = $"[gray]{Markup.Escape(r.FileName)} (up to date)[/]";
                        t.Value = t.MaxValue;
                    }
                    else if (r.NotModified)
                    {
                        t.Description = $"[gray]{Markup.Escape(r.FileName)} (not modified)[/]";
                        t.Value = t.MaxValue;
                    }
                    else if (r.Stale)
                    {
                        t.Description = $"[yellow]{Markup.Escape(r.FileName)} (stale, update failed: {Markup.Escape(r.ErrorMessage ?? "")})[/]";
                        t.Value = t.MaxValue;
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
    }

    // Actual byte size of a data file on disk, or 0 when it is missing or unreadable.
    private long FileSizeOnDisk(string fileName)
    {
        try
        {
            var info = new FileInfo(Path.Combine(_dataDir, fileName));
            return info.Exists ? info.Length : 0;
        }
        catch
        {
            return 0;
        }
    }

    // An ordinary run restores only required data. The update command restores optional data.
    private async Task RunSilentAsync(CancellationTokenSource cts)
    {
        var missingFiles = _files
            .Where(file => ForegroundRequiredFiles.Contains(file.FileName)
                && !_storage.IsFileValid(file.FileName, file.MinSize))
            .ToList();
        if (missingFiles.Count == 0) return;

        AnsiConsole.MarkupLine("[dim]Restoring the required IP-to-ASN database...[/]");

        using var http = DownloadManagerFactory.CreateHttpClient(_options);
        var manager = new DownloadManager(
            DownloadManagerFactory.CreateDownloader(http), _storage, missingFiles, _meta);

        var results = await ExecuteWithBypassRetryAsync(
            manager, missingFiles, progressFactory: null, force: false, cts);

        // Quiet mode: report only a hard failure (the file did not update and there is no valid copy).
        if (results.Any(r => !r.Success || r.Stale) && !cts.IsCancellationRequested)
            AnsiConsole.MarkupLine("[dim]Some data updates failed; using cached copies.[/]");
    }

    // The shared download path retries over the physical interface after the system route fails.
    private async Task<IReadOnlyList<FileDownloadResult>> ExecuteWithBypassRetryAsync(
        DownloadManager manager,
        IReadOnlyList<FileDescriptor> files,
        Func<FileDescriptor, IProgress<DownloadProgress>?>? progressFactory,
        bool force,
        CancellationTokenSource cts)
    {
        var results = await manager.DownloadAllDetailedAsync(
            _options, progressFactory, force,
            maxDegreeOfParallelism: 3, cancellationToken: cts.Token);

        if (results.Any(r => !r.Success || r.Stale) && !cts.IsCancellationRequested)
        {
            var bypass = NetworkInterfaceHelper.CreateBypassVpnHttpClient(
                TimeSpan.FromSeconds(_options.TimeoutSeconds));
            if (bypass != null)
            {
                using (bypass)
                {
                    bypass.DefaultRequestHeaders.UserAgent.ParseAdd("SubnetSearch/1.0");
                    var retryManager = new DownloadManager(
                        DownloadManagerFactory.CreateDownloader(bypass), _storage, files, _meta);
                    var retryResults = await retryManager.DownloadAllDetailedAsync(
                        _options, progressFactory, force,
                        maxDegreeOfParallelism: 3, cancellationToken: cts.Token);

                    // IN-04: the contract is not guaranteed across the module boundary. If the retry
                    // set does not contain a file, keep the original result instead of throwing.
                    results = results
                        .Select(r => r.Success && !r.Stale
                            ? r
                            : retryResults.FirstOrDefault(x => x.FileName == r.FileName) ?? r)
                        .ToList();
                }
            }
        }

        return results;
    }
}
