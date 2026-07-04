using SubnetSearch.Classification;
using SubnetSearch.Core.Utilities;
using SubnetSearch.Cli.Rendering;

namespace SubnetSearch.Cli.Commands;

public sealed class CidrCommand(CliContext ctx, string cidr) : ICommand
{
    public async Task<int> ExecuteAsync(CancellationToken ct)
    {
        if (!IpConverter.TryParseCidr(cidr, out uint start, out uint end))
            throw new ArgumentException($"Invalid CIDR: {cidr}");

        long totalIps = (long)end - start + 1;

        int warnThreshold = ctx.ForceWhois ? 50 : 256;
        if (totalIps > warnThreshold)
        {
            if (ctx.ForceWhois)
            {
                long minMin = totalIps * 1 / 60;
                long maxMin = totalIps * 4 / 60;
                AnsiConsole.MarkupLine($"[yellow]Range: {totalIps} addresses. With --whois, estimated time: {minMin}–{maxMin} min.[/]");
            }
            else
            {
                AnsiConsole.MarkupLine($"[yellow]Range contains {totalIps} addresses. Processing may take a while.[/]");
            }
            if (!AnsiConsole.Confirm("Continue?"))
                return 0;
        }

        var batchClassifier = await ClassifierFactory.CreateBatchClassifierAsync(ctx.DataDir, ctx.ForceWhois, ctx.PeeringDbHttp);

        // Guard against ranges too large to hold in memory.
        if (totalIps > 1_000_000)
            throw new ArgumentException($"CIDR range too large ({totalIps:N0} addresses). Use -l with a pre-generated file.");

        var ips = new List<string>((int)totalIps);
        // Iterate without post-increment past uint.MaxValue: add last element separately.
        for (uint current = start; current != end; current++)
            ips.Add(IpConverter.UintToIp(current));
        ips.Add(IpConverter.UintToIp(end));

        IReadOnlyList<ClassificationResult> results = [];
        await AnsiConsole.Progress()
            .AutoClear(false)
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("[green]Scanning CIDR[/]", maxValue: totalIps);
                results = await batchClassifier.ClassifyIpsAsync(ips,
                    new Progress<BatchProgress>(p => task.Value = p.ProcessedItems), ct);
                task.StopTask();
            });

        Console.WriteLine();
        int hostingCount = results.Count(r => r.IsHosting);
        double percent   = totalIps > 0 ? (double)hostingCount / totalIps * 100 : 0;
        AnsiConsole.MarkupLine($"Hosting addresses: [green]{hostingCount}[/] of [blue]{totalIps}[/] ({percent:F1}%)");
        ClassificationRenderer.PrintTable(ips.Zip(results).Select(t => (t.First, t.Second)).ToList());
        return 0;
    }
}
