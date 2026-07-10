using SubnetSearch.Network;
using SubnetSearch.Core.Models.Data;

namespace SubnetSearch.Cli;

/// <summary>
/// Единая точка провижининга data-файлов. Решает режим (<see cref="ProvisioningStatus.Decide"/>)
/// и исполняет его:
///   Visible — установка / <c>rover update</c> / первый запуск: полная таблица прогресса Spectre;
///   Silent  — обычный запуск с устаревшими файлами: одна dim-строка, загрузка без таблицы;
///   None    — всё свежее: ничего не качаем и не печатаем (HTTP даже не поднимаем).
/// Ядро загрузки (DownloadManager + retry через bypass-VPN) общее для Visible и Silent.
/// </summary>
public sealed class DataProvisioner
{
    private readonly IReadOnlyList<FileDescriptor> _files;
    private readonly SubnetSearch.Core.Interfaces.Data.IFileStorage _storage;
    private readonly FileMetadataStore _meta;
    private readonly DownloadOptions _options;

    public DataProvisioner(string dataDir)
    {
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

    /// <summary>Выбирает режим и исполняет его. Ничего не делает в режиме None.</summary>
    public async Task ProvisionAsync(bool isUpdateCommand, CancellationTokenSource cts)
    {
        var status = new ProvisioningStatus(_storage, _files, _meta);
        var mode   = ProvisioningStatus.Decide(isUpdateCommand, status.AnyFileValid(), status.AnyPending());

        switch (mode)
        {
            case ProvisioningMode.Visible: await RunVisibleAsync(cts); break;
            case ProvisioningMode.Silent:  await RunSilentAsync(cts);  break;
            // None — сознательно ничего.
        }
    }

    // ── Visible: полная таблица прогресса (установка / update / первый запуск) ──────────────
    private async Task RunVisibleAsync(CancellationTokenSource cts)
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
                        if (p.TotalBytes.HasValue && t.MaxValue != p.TotalBytes.Value)
                            t.MaxValue = p.TotalBytes.Value;
                        t.Value = p.BytesDownloaded;
                    });
                };

                var results = await ExecuteWithBypassRetryAsync(manager, progressFactory, cts);

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
    }

    // ── Silent: одна dim-строка, загрузка без таблицы (обычный запуск, есть устаревшее) ──────
    private async Task RunSilentAsync(CancellationTokenSource cts)
    {
        AnsiConsole.MarkupLine("[dim]Updating databases...[/]");

        using var http = DownloadManagerFactory.CreateHttpClient(_options);
        var manager = new DownloadManager(
            DownloadManagerFactory.CreateDownloader(http), _storage, _files, _meta);

        var results = await ExecuteWithBypassRetryAsync(manager, progressFactory: null, cts);

        // Тихо: сообщаем только о жёстком провале (файл не обновился и нет валидной копии).
        if (results.Any(r => !r.Success) && !cts.IsCancellationRequested)
            AnsiConsole.MarkupLine("[dim]Some data updates failed; using cached copies.[/]");
    }

    // ── Общее ядро: system-route загрузка + retry по физическому интерфейсу (bypass VPN) ─────
    private async Task<IReadOnlyList<FileDownloadResult>> ExecuteWithBypassRetryAsync(
        DownloadManager manager,
        Func<FileDescriptor, IProgress<DownloadProgress>?>? progressFactory,
        CancellationTokenSource cts)
    {
        var results = await manager.DownloadAllDetailedAsync(
            _options, progressFactory, maxDegreeOfParallelism: 3, cancellationToken: cts.Token);

        if (results.Any(r => !r.Success) && !cts.IsCancellationRequested)
        {
            var bypass = NetworkInterfaceHelper.CreateBypassVpnHttpClient(
                TimeSpan.FromSeconds(_options.TimeoutSeconds));
            if (bypass != null)
            {
                using (bypass)
                {
                    bypass.DefaultRequestHeaders.UserAgent.ParseAdd("SubnetSearch/1.0");
                    var retryManager = new DownloadManager(
                        DownloadManagerFactory.CreateDownloader(bypass), _storage, _files, _meta);
                    var retryResults = await retryManager.DownloadAllDetailedAsync(
                        _options, progressFactory, maxDegreeOfParallelism: 3, cancellationToken: cts.Token);

                    // IN-04: контракт не гарантирован на границе модуля — если retry-набор не
                    // содержит файла, оставляем исходный результат вместо исключения.
                    results = results
                        .Select(r => r.Success
                            ? r
                            : retryResults.FirstOrDefault(x => x.FileName == r.FileName) ?? r)
                        .ToList();
                }
            }
        }

        return results;
    }
}
