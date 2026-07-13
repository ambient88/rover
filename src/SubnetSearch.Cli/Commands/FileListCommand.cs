using SubnetSearch.Classification;
using SubnetSearch.Cli.Rendering;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Cli.Commands;

public sealed class FileListCommand(CliContext ctx, string filePath) : ICommand
{
    public async Task<int> ExecuteAsync(CancellationToken ct)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"File not found: {filePath}");

        const long MaxFileSizeBytes = 50L * 1024 * 1024; // 50 MB
        var fileInfo = new FileInfo(filePath);
        if (fileInfo.Length > MaxFileSizeBytes)
            throw new InvalidOperationException(
                $"File too large: {fileInfo.Length / 1024 / 1024} MB (max 50 MB). Split the file and run in batches.");

        var lines = await File.ReadAllLinesAsync(filePath, ct);
        var items = lines.Where(l => !string.IsNullOrWhiteSpace(l)).Select(l => l.Trim()).ToList();

        if (items.Count == 0)
            throw new InvalidOperationException("File is empty.");

        using var batchClassifier = await ClassifierFactory.CreateBatchClassifierAsync(ctx.DataDir, ctx.ForceWhois, ctx.PeeringDbHttp, ctx.Config.PeeringDbKey);
        var ips     = new List<string>();
        var domains = new List<string>();

        int skippedIpv6 = 0;
        foreach (var item in items)
        {
            switch (BatchInputClassifier.Classify(item))
            {
                case BatchInputKind.Ipv4:
                    ips.Add(item);
                    break;
                case BatchInputKind.Domain:
                    domains.Add(item);
                    break;
                case BatchInputKind.Ipv6Unsupported:
                    // IPv6 is skipped because the classification pipeline supports IPv4 only.
                    skippedIpv6++;
                    AnsiConsole.MarkupLine($"[yellow]Skipped: {Markup.Escape(item)} (IPv6 is not supported)[/]");
                    break;
                default:
                    AnsiConsole.MarkupLine($"[yellow]Skipped: {Markup.Escape(item)} (not an IP or domain)[/]");
                    break;
            }
        }

        if (skippedIpv6 > 0)
            AnsiConsole.MarkupLine($"[dim]{skippedIpv6} IPv6 address(es) skipped (IPv4-only).[/]");

        IReadOnlyList<ClassificationResult> ipResults         = [];
        IReadOnlyList<DomainClassificationResult> domainResults = [];

        await AnsiConsole.Progress()
            .AutoClear(false)
            .Columns(new ProgressColumn[] { new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn() })
            .StartAsync(async ctx =>
            {
                var ipTask     = ips.Count > 0    ? ctx.AddTask($"[green]IPs ({ips.Count})[/]",          maxValue: ips.Count)     : null;
                var domainTask = domains.Count > 0 ? ctx.AddTask($"[green]Domains ({domains.Count})[/]",  maxValue: domains.Count) : null;

                var classifyIps = ips.Count > 0
                    ? batchClassifier.ClassifyIpsAsync(ips,
                        new Progress<BatchProgress>(p => { if (ipTask != null) ipTask.Value = p.ProcessedItems; }), ct)
                    : Task.FromResult<IReadOnlyList<ClassificationResult>>([]);

                var classifyDomains = domains.Count > 0
                    ? batchClassifier.ClassifyDomainsAsync(domains,
                        new Progress<BatchProgress>(p => { if (domainTask != null) domainTask.Value = p.ProcessedItems; }), ct)
                    : Task.FromResult<IReadOnlyList<DomainClassificationResult>>([]);

                await Task.WhenAll(classifyIps, classifyDomains);
                ipResults     = classifyIps.Result;
                domainResults = classifyDomains.Result;
            });

        if (ips.Count > 0)
        {
            AnsiConsole.MarkupLine("\n[bold]IP results:[/]");
            var ipTable = new Table();
            ipTable.AddColumn("IP");
            ipTable.AddColumn("Hosting");
            ipTable.AddColumn("ASN");
            ipTable.AddColumn("Organization");
            ipTable.AddColumn("Type");
            ipTable.AddColumn("Website");
            foreach (var (ip, r) in ips.Zip(ipResults))
            {
                string hosting = r.IsHosting ? "[green]Yes[/]" : "[yellow]No[/]";
                ipTable.AddRow(
                    Markup.Escape(ip),
                    hosting,
                    Markup.Escape(r.Asn?.ToString() ?? "N/A"),
                    Markup.Escape(r.Organization ?? "N/A"),
                    Markup.Escape(r.HostingType?.ToString() ?? "N/A"),
                    r.Website != null ? SafeMarkup.Link(r.Website) : "N/A"
                );
            }
            AnsiConsole.Write(ipTable);
        }

        if (domains.Count > 0)
        {
            AnsiConsole.MarkupLine("\n[bold]Domain results:[/]");
            foreach (var dr in domainResults)
                DomainRenderer.PrintDomainResult(dr);
        }

        return 0;
    }
}
