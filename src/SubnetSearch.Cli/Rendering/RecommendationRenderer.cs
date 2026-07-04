namespace SubnetSearch.Cli.Rendering;

public static class RecommendationRenderer
{
    public static void PrintRecommendations(
        string region,
        IReadOnlyList<ProviderRecommendation> results,
        bool hasAbuseIpDb, bool hasGreyNoise,
        bool showInRoute = false)
    {
        AnsiConsole.MarkupLine($"[bold cyan]══ Providers in {Markup.Escape(region)} ({results.Count} found) ══[/]");
        Console.WriteLine();

        if (results.Count > 0 && results.All(r => !r.LatencyMs.HasValue))
            AnsiConsole.MarkupLine("[dim]Note: latency not measured — ICMP may be blocked in this environment.[/]\n");

        for (int i = 0; i < results.Count; i++)
        {
            var r     = results[i];
            var score = (int)(r.Score * 100);
            var scoreColor = score >= 70 ? "green" : score >= 40 ? "yellow" : "red";

            AnsiConsole.MarkupLine(
                $"  [bold]#{i + 1,2}[/]  [{scoreColor}]{score,3}/100[/]  " +
                $"[bold]{Markup.Escape(r.Organization)}[/]  [dim]AS{r.Asn}[/]");

            if (!string.IsNullOrWhiteSpace(r.Country))
                AnsiConsole.MarkupLine($"        Country:    {Markup.Escape(r.Country)}");

            if (r.LatencyMs.HasValue)
            {
                string latency = $"{r.LatencyMs.Value:F1} ms";
                if (r.PacketLoss.HasValue && r.PacketLoss.Value > 0)
                    latency += $"  [yellow]loss: {r.PacketLoss.Value:F0}%[/]";
                AnsiConsole.MarkupLine($"        Latency:    {latency}  [dim](→ {Markup.Escape(r.AnchorIp ?? "")})[/]");
            }

            if (r.PeeringCount.HasValue)
                AnsiConsole.MarkupLine($"        Peerings:   {r.PeeringCount.Value}");
            if (r.UpstreamCount > 0)
                AnsiConsole.MarkupLine($"        Upstreams:  {r.UpstreamCount}");
            AnsiConsole.MarkupLine($"        Prefixes:   {r.PrefixCount}" +
                (r.HasIPv6 ? $"  [dim]+{r.IPv6PrefixCount} IPv6[/]" : ""));
            if (r.TotalIpCount > 0)
            {
                string ipPool = r.TotalIpCount >= 1_000_000
                    ? $"{r.TotalIpCount / 1_000_000.0:F1}M"
                    : r.TotalIpCount >= 1_000
                        ? $"{r.TotalIpCount / 1000.0:F0}K"
                        : r.TotalIpCount.ToString();
                AnsiConsole.MarkupLine($"        IP Pool:    {ipPool} addresses");
            }

            if (r.TotalListIps > 0)
            {
                double pct     = 100.0 * r.CoverageCount / r.TotalListIps;
                var color      = pct >= 10 ? "green" : pct >= 2 ? "yellow" : "dim";
                string density = r.TotalIpCount > 0 && r.CoverageCount > 0
                    ? $"  [dim]density: {(double)r.CoverageCount / r.TotalIpCount * 1_000_000:F0}/1M[/]"
                    : "";
                AnsiConsole.MarkupLine(
                    $"        [{color}]Coverage:[/]   {r.CoverageCount}/{r.TotalListIps} IPs ({pct:F1}%){density}");
            }

            if (r.RpkiScore.HasValue)
            {
                int rpkiPct = (int)(r.RpkiScore.Value * 100);
                string rpkiColor = rpkiPct >= 80 ? "green" : rpkiPct >= 50 ? "yellow" : "red";
                AnsiConsole.MarkupLine($"        RPKI:       [{rpkiColor}]{rpkiPct}% valid[/]");
            }

            if (r.AbuserScore.HasValue)
            {
                var pct   = (int)(r.AbuserScore.Value * 100);
                var color = pct < 10 ? "green" : pct < 40 ? "yellow" : "red";
                AnsiConsole.MarkupLine($"        Reputation: [{color}]{pct}% abuser score[/]");
            }

            // Score breakdown
            if (r.Breakdown != null)
            {
                var b = r.Breakdown;
                var parts = new List<string>
                {
                    $"L:{(int)(b.Latency * 100)}",
                    $"P:{(int)(b.Peering * 100)}",
                    $"Rep:{(int)(b.Reputation * 100)}",
                    $"Size:{(int)(b.Size * 100)}",
                };
                if (b.Rpki.HasValue) parts.Add($"RPKI:{(int)(b.Rpki.Value * 100)}");
                AnsiConsole.MarkupLine($"        [dim]Score:      {string.Join(" · ", parts)}[/]");
            }

            if (!string.IsNullOrWhiteSpace(r.Website))
                AnsiConsole.MarkupLine($"        Website:    [link={r.Website}]{Markup.Escape(r.Website)}[/]");
            if (!string.IsNullOrWhiteSpace(r.PricingUrl))
                AnsiConsole.MarkupLine($"        [green]Pricing:[/]    [link={r.PricingUrl}]{Markup.Escape(r.PricingUrl)}[/]");
            if (showInRoute && r.InRoute)
                AnsiConsole.MarkupLine($"        [green]In route:[/]   AS{r.Asn} seen in traceroute path");

            Console.WriteLine();
        }

        if (!hasAbuseIpDb || !hasGreyNoise)
        {
            AnsiConsole.MarkupLine("[dim]Add API keys for deeper reputation scoring:[/]");
            if (!hasAbuseIpDb)
                AnsiConsole.MarkupLine("[dim]  rover --set-key abuseipdb=YOUR_KEY  (free at abuseipdb.com)[/]");
            if (!hasGreyNoise)
                AnsiConsole.MarkupLine("[dim]  rover --set-key greynoise=YOUR_KEY  (free at greynoise.io)[/]");
            Console.WriteLine();
        }
    }
}
