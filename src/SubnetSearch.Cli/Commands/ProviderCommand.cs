using SubnetSearch.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Network;
using SubnetSearch.Network.Recommend;
using SubnetSearch.Cli.Rendering;

namespace SubnetSearch.Cli.Commands;

public sealed class ProviderCommand(CliContext ctx, string query) : ICommand
{
    public async Task<int> ExecuteAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(query))
            throw new ArgumentException("Provide an ASN (e.g. AS213520 or 213520) or provider name.");

        AnsiConsole.MarkupLine($"[cyan]Looking up provider: {Markup.Escape(query)}[/]\n");

        // CLI wires Classification and Network together directly.
        var peeringDbRes = new PeeringDbWebsiteResolver(ctx.PeeringDbHttp, ctx.Config.PeeringDbKey);
        var websiteRes   = new HostingWebsiteResolver([], [], peeringDbRes);
        var ripeCache    = await RipeStatCache.LoadAsync(ctx.DataDir);
        var ripeClient   = new RipeStatClient(ctx.PeeringDbHttp, ripeCache);
        var records      = await new Ip2AsnLoader().LoadAsync(Path.Combine(ctx.DataDir, "ip2asn-v4.tsv.gz"));
        var ipIndex      = new IpRangeIndex(records);
        var scanner      = new ProviderScanner(ripeClient, websiteRes, ipIndex);

        ProviderScanResult? result;
        try
        {
            result = await scanner.ScanAsync(query, ct);
        }
        finally
        {
            await ripeCache.FlushIfDirtyAsync();
        }

        if (result == null)
        {
            AnsiConsole.MarkupLine("[red]Provider not found.[/]");
            return 0;
        }

        ProviderRenderer.PrintProviderResult(result);
        return 0;
    }
}
