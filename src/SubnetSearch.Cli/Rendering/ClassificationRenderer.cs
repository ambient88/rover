namespace SubnetSearch.Cli.Rendering;

public static class ClassificationRenderer
{
    public static void PrintResult(
        string ip,
        ClassificationResult result,
        PingStats? ping = null,
        TracerouteAnalysis? traceroute = null,
        IReadOnlyList<int>? openPorts = null,
        HttpFingerprintResult? http = null)
    {
        if (!string.IsNullOrEmpty(ip))
            AnsiConsole.MarkupLine($"[cyan]IP: {Markup.Escape(ip)}[/]");

        // Show the node type when a CDN IP is queried directly with -a.
        // An HTTP response indicates Tunnel. No HTTP service indicates WARP.
        if (!string.IsNullOrEmpty(ip))
        {
            var rawProduct = SubnetSearch.Network.Http.CloudflareProductDetector.DetectFromIp(ip);
            if (rawProduct != null)
            {
                string resolved = http?.CdnProduct                                     // Already disambiguated by HttpFingerprintService
                               ?? (rawProduct == "Ambiguous" ? "Cloudflare WARP" : rawProduct);
                AnsiConsole.MarkupLine($"  [bold]Node type:[/]    Cloudflare [dim]({Markup.Escape(resolved)})[/]");
            }
        }

        AnsiConsole.MarkupLine($"  [bold]Hosting:[/]      {(result.IsHosting ? "[green]Yes[/]" : "[yellow]No[/]")}");
        AnsiConsole.MarkupLine($"  [bold]ASN:[/]          {Markup.Escape(result.Asn?.ToString() ?? "N/A")}");
        AnsiConsole.MarkupLine($"  [bold]Organization:[/] {Markup.Escape(result.Organization ?? "N/A")}");
        if (!string.IsNullOrWhiteSpace(result.IpRange))
            AnsiConsole.MarkupLine($"  [bold]IP range:[/]     {Markup.Escape(result.IpRange)}");
        if (!string.IsNullOrWhiteSpace(result.Ptr))
            AnsiConsole.MarkupLine($"  [bold]PTR:[/]          {Markup.Escape(result.Ptr)}");
        AnsiConsole.MarkupLine($"  [bold]Country:[/]      {Markup.Escape(result.Country ?? "N/A")}");
        if (!string.IsNullOrWhiteSpace(result.City))
        {
            string geo = result.Region != null ? $"{result.City}, {result.Region}" : result.City;
            if (result.Latitude.HasValue && result.Longitude.HasValue)
                geo += $" ({result.Latitude.Value:F4}, {result.Longitude.Value:F4})";
            if (!string.IsNullOrWhiteSpace(result.Timezone))
                geo += $" · {result.Timezone}";
            AnsiConsole.MarkupLine($"  [bold]Location:[/]     {Markup.Escape(geo)}");
        }
        if (!string.IsNullOrWhiteSpace(result.Rir))
            AnsiConsole.MarkupLine($"  [bold]RIR:[/]          {Markup.Escape(result.Rir)}");
        if (result.HostingType.HasValue)
            AnsiConsole.MarkupLine($"  [bold]Hosting type:[/] {Markup.Escape(result.HostingType.Value.ToString())}");
        if (result.PeeringCount.HasValue)
            AnsiConsole.MarkupLine($"  [bold]Peerings (IXP):[/] {result.PeeringCount.Value}");
        if (result.IxLocations is { Count: > 0 })
            AnsiConsole.MarkupLine($"  [bold]Regions:[/]      {Markup.Escape(string.Join(", ", result.IxLocations))}");
        if (result.RegistrationDate.HasValue)
            AnsiConsole.MarkupLine($"  [bold]Registered:[/]   {result.RegistrationDate.Value:yyyy-MM-dd}");
        if (result.UpdatedDate.HasValue)
            AnsiConsole.MarkupLine($"  [bold]Updated:[/]      {result.UpdatedDate.Value:yyyy-MM-dd}");
        if (!string.IsNullOrWhiteSpace(result.Status))
            AnsiConsole.MarkupLine($"  [bold]Status:[/]       {Markup.Escape(result.Status)}");
        if (!string.IsNullOrWhiteSpace(result.AbuseEmail))
            AnsiConsole.MarkupLine($"  [bold]Abuse contact:[/] {Markup.Escape(result.AbuseEmail)}");
        if (result.ReputationScore.HasValue)
        {
            string rep = result.ReputationScore.Value switch
            {
                0    => "[green]Clean[/]",
                1    => "[yellow]Flagged (1 source)[/]",
                <= 4 => $"[yellow]Suspicious ({result.ReputationScore.Value} sources)[/]",
                _    => $"[red]High risk ({result.ReputationScore.Value} sources)[/]"
            };
            AnsiConsole.MarkupLine($"  [bold]Reputation:[/]   {rep}");
        }
        if (!string.IsNullOrWhiteSpace(result.Website))
            AnsiConsole.MarkupLine($"  [bold]Website:[/]      {SafeMarkup.Link(result.Website)}");
        else
            AnsiConsole.MarkupLine($"  [bold]Website:[/]      No data");
        AnsiConsole.MarkupLine($"  [bold]Source:[/]       {Markup.Escape(result.Source)}");

        if (ping != null)
        {
            string loss = ping.PacketLoss > 0 ? $" [yellow]loss: {ping.PacketLoss}%[/]" : "";
            AnsiConsole.MarkupLine(
                $"  [bold]Latency:[/]      min {ping.MinMs:F1}ms / avg {ping.AvgMs:F1}ms / max {ping.MaxMs:F1}ms{loss}");
        }
        if (openPorts is { Count: > 0 })
            AnsiConsole.MarkupLine($"  [bold]Open ports:[/]   {string.Join(", ", openPorts)}");
        else if (openPorts != null)
            AnsiConsole.MarkupLine("  [bold]Open ports:[/]   [dim]no response on 22/80/443/3306/8080/8443[/]");
        if (traceroute?.Hops is { Count: > 0 })
        {
            AnsiConsole.MarkupLine("  [bold]Traceroute:[/]");
            foreach (var h in traceroute.Hops)
            {
                string addr    = h.Hop.IpAddress ?? "*";
                string latency = h.Hop.LatencyMs.HasValue ? $"{h.Hop.LatencyMs.Value:F1} ms" : "timeout";
                string ptr     = h.Ptr != null ? $" [dim]({Markup.Escape(h.Ptr)})[/]" : "";

                if (h.Kind == HopKind.ProxyCdn)
                {
                    string hint = h.ProxyHint != null ? $" [yellow]← {Markup.Escape(h.ProxyHint)}[/]" : "";
                    AnsiConsole.MarkupLine(
                        $"    [dim]{h.Hop.HopNumber,2}[/]  [yellow]{Markup.Escape(addr),-18}[/] {latency}{ptr}{hint}");
                }
                else if (h.Kind == HopKind.Timeout)
                {
                    AnsiConsole.MarkupLine($"    [dim]{h.Hop.HopNumber,2}  *                  timeout[/]");
                }
                else
                {
                    AnsiConsole.MarkupLine($"    [dim]{h.Hop.HopNumber,2}[/]  {Markup.Escape(addr),-18} {latency}{ptr}");
                }
            }

            // Show the hidden route block when a proxy or CDN is followed only by timeouts.
            if (traceroute.LikelyHiddenRoute)
            {
                Console.WriteLine();
                AnsiConsole.MarkupLine("  [bold yellow]── Hidden route detected ──[/]");
                if (traceroute.HiddenBehind != null)
                    AnsiConsole.MarkupLine($"  [yellow]Proxy/CDN:[/] {Markup.Escape(traceroute.HiddenBehind)}");
                AnsiConsole.MarkupLine($"  [dim]Trailing timeouts: {traceroute.TrailingTimeouts} hops[/]");
                AnsiConsole.MarkupLine("  [dim]The route from this proxy to the real backend is not visible[/]");
                AnsiConsole.MarkupLine("  [dim]from traceroute — traffic is forwarded at the application layer.[/]");
            }
        }
        if (http != null)
            PrintHttpBlock(http);
        Console.WriteLine();
    }

    public static void PrintHttpBlock(HttpFingerprintResult http)
    {
        if (!string.IsNullOrWhiteSpace(http.CdnProvider))
        {
            string cdnLabel = string.IsNullOrWhiteSpace(http.CdnProduct)
                ? Markup.Escape(http.CdnProvider)
                : $"{Markup.Escape(http.CdnProvider)} [dim]({Markup.Escape(http.CdnProduct)})[/]";
            AnsiConsole.MarkupLine($"  [bold]Behind CDN:[/]   {cdnLabel}");
            AnsiConsole.MarkupLine("  [dim]  Real hosting provider and server location are hidden behind the CDN.[/]");
        }
        if (!string.IsNullOrWhiteSpace(http.ServerHeader))
            AnsiConsole.MarkupLine($"  [bold]Server:[/]       {Markup.Escape(http.ServerHeader)}");
        if (!string.IsNullOrWhiteSpace(http.XPoweredBy))
            AnsiConsole.MarkupLine($"  [bold]X-Powered-By:[/] {Markup.Escape(http.XPoweredBy)}");
        if (http.HttpsRedirect.HasValue)
            AnsiConsole.MarkupLine($"  [bold]HTTPS:[/]        {(http.HttpsRedirect.Value ? "[green]redirects ✓[/]" : "[yellow]no redirect[/]")}");
        if (!string.IsNullOrWhiteSpace(http.TlsIssuer) || http.TlsExpiry.HasValue)
        {
            var tls = "";
            if (!string.IsNullOrWhiteSpace(http.TlsIssuer)) tls += Markup.Escape(http.TlsIssuer);
            if (http.TlsExpiry.HasValue)
            {
                string expStr = $"expires {http.TlsExpiry.Value:yyyy-MM-dd}";
                tls += tls.Length > 0 ? $" · {expStr}" : expStr;
                if (http.TlsExpired == true) tls += " [red](EXPIRED)[/]";
            }
            if (!string.IsNullOrWhiteSpace(http.TlsVersion))
                tls += $" · {Markup.Escape(http.TlsVersion)}";
            AnsiConsole.MarkupLine($"  [bold]TLS:[/]          {tls}");
        }

        if (http.ProxyHeaders is { Count: > 0 })
        {
            AnsiConsole.MarkupLine("  [bold]Proxy headers:[/]");
            foreach (var (name, value) in http.ProxyHeaders)
                AnsiConsole.MarkupLine($"    [dim]{Markup.Escape(name)}:[/] {Markup.Escape(value)}");
        }
    }

    public static void PrintTable(List<(string ip, ClassificationResult res)> results)
    {
        var table = new Table();
        table.AddColumn("IP");
        table.AddColumn("Hosting");
        table.AddColumn("ASN");
        table.AddColumn("Organization");
        table.AddColumn("Type");
        table.AddColumn("Website");

        foreach (var (ip, res) in results)
        {
            string hosting = res.IsHosting ? "[green]Yes[/]" : "[yellow]No[/]";
            table.AddRow(
                Markup.Escape(ip),
                hosting,
                Markup.Escape(res.Asn?.ToString() ?? "N/A"),
                Markup.Escape(res.Organization ?? "N/A"),
                Markup.Escape(res.HostingType?.ToString() ?? "N/A"),
                res.Website != null ? SafeMarkup.Link(res.Website) : "N/A"
            );
        }

        AnsiConsole.Write(table);
    }
}
