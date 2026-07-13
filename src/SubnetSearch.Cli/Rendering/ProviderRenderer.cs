namespace SubnetSearch.Cli.Rendering;

public static class ProviderRenderer
{
    public static void PrintProviderResult(ProviderScanResult r)
    {
        string title = string.IsNullOrWhiteSpace(r.Organization) ? $"AS{r.Asn}" : r.Organization;
        AnsiConsole.MarkupLine($"[bold cyan]══ Provider: {Markup.Escape(title)} (AS{r.Asn}) ══[/]");
        Console.WriteLine();

        if (!string.IsNullOrWhiteSpace(r.AsnHandle))
            AnsiConsole.MarkupLine($"  [bold]ASN Handle:[/]    {Markup.Escape(r.AsnHandle)}");
        if (!string.IsNullOrWhiteSpace(r.CountryCode))
            AnsiConsole.MarkupLine($"  [bold]Country:[/]       {Markup.Escape(r.CountryCode)}");
        if (!string.IsNullOrWhiteSpace(r.InfoType))
            AnsiConsole.MarkupLine($"  [bold]Network type:[/]  {Markup.Escape(r.InfoType)}");
        if (!string.IsNullOrWhiteSpace(r.Website))
            AnsiConsole.MarkupLine($"  [bold]Website:[/]       {SafeMarkup.Link(r.Website)}");
        if (r.PeeringCount.HasValue)
            AnsiConsole.MarkupLine($"  [bold]Peerings (IXP):[/] {r.PeeringCount.Value}");
        if (r.IxLocations is { Count: > 0 })
            AnsiConsole.MarkupLine($"  [bold]Regions:[/]       {Markup.Escape(string.Join(", ", r.IxLocations))}");

        Console.WriteLine();

        int prefixCount = r.Prefixes.Count;
        long totalIps   = r.TotalIpCount;
        AnsiConsole.MarkupLine($"  [bold]── IPv4 prefixes ({prefixCount} subnets, {totalIps:N0} IPs) ──[/]");
        if (prefixCount == 0)
        {
            AnsiConsole.MarkupLine("  [dim]No data[/]");
        }
        else
        {
            foreach (var p in r.Prefixes)
            {
                string cc   = p.CountryCode ?? "??";
                string desc = p.Description ?? "";
                AnsiConsole.MarkupLine(
                    $"  [green]{Markup.Escape(p.Prefix),-22}[/] {Markup.Escape(cc)}  " +
                    $"[dim]{p.IpCount,8:N0} IPs   {Markup.Escape(desc)}[/]");
            }
        }

        Console.WriteLine();

        AnsiConsole.MarkupLine("  [bold]── Upstreams (transit providers) ──[/]");
        if (r.Upstreams.Count == 0)
        {
            AnsiConsole.MarkupLine("  [dim]No data[/]");
        }
        else
        {
            foreach (var u in r.Upstreams)
            {
                string name = u.Description ?? u.Name ?? $"AS{u.Asn}";
                string cc   = u.CountryCode != null ? $" ({u.CountryCode})" : "";
                AnsiConsole.MarkupLine($"  [yellow]AS{u.Asn,-8}[/] {Markup.Escape(name)}{Markup.Escape(cc)}");
            }
        }

        if (r.OtherCandidates is { Count: > 0 })
        {
            Console.WriteLine();
            AnsiConsole.MarkupLine("[dim]  Also found (use -o AS<number> for a specific lookup):[/]");
            foreach (var (asn, name, desc) in r.OtherCandidates.Take(4))
            {
                string label = desc ?? name ?? $"AS{asn}";
                AnsiConsole.MarkupLine($"  [dim]  AS{asn}  {Markup.Escape(label)}[/]");
            }
        }

        Console.WriteLine();
    }
}
