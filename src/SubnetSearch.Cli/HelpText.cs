namespace SubnetSearch.Cli;

public static class HelpText
{
    public static void ShowHelp()
    {
        AnsiConsole.MarkupLine("[yellow]Usage:[/]");
        AnsiConsole.MarkupLine("[yellow]Analyze:[/]");
        AnsiConsole.MarkupLine("  -a <ip>              Classify a single IP address");
        AnsiConsole.MarkupLine("  -d <domain>          Classify a domain");
        AnsiConsole.MarkupLine("  -c <CIDR>            Classify a CIDR range");
        AnsiConsole.MarkupLine("  -l <file>            Batch classify from file (IPs or domains, one per line)");
        AnsiConsole.MarkupLine("  -o <ASN|name>        Scan a provider: prefixes, upstreams, peerings");
        AnsiConsole.MarkupLine("  --whois              Force WHOIS lookups for each IP (extra data)");
        Console.WriteLine();
        AnsiConsole.MarkupLine("[yellow]Discover:[/]");
        AnsiConsole.MarkupLine("  -r                   Find and rank hosting providers worldwide");
        AnsiConsole.MarkupLine("  -r <region>          Search by IXP region (e.g. Frankfurt, Amsterdam)");
        AnsiConsole.MarkupLine("  --type <type>        Filter by provider type:");
        AnsiConsole.MarkupLine("                         server          — all server rental, umbrella = vps + dedicated + cloud  [[alias: hosting]]");
        AnsiConsole.MarkupLine("                         vps             — virtual servers only (excludes bare-metal-only and cloud-only providers)");
        AnsiConsole.MarkupLine("                         dedicated       — bare-metal / dedicated servers only (curated list in data/asn-exclusions.json)");
        AnsiConsole.MarkupLine("                         cloud           — hyperscalers only (AWS, Azure, GCP, ... — curated list in data/asn-exclusions.json)");
        AnsiConsole.MarkupLine("                         cdn / content   — CDN and content networks");
        AnsiConsole.MarkupLine("                         nsp / isp / transit  — Network service providers");
        AnsiConsole.MarkupLine("                         ai              — AI/GPU-only cloud providers (CoreWeave, Lambda, Crusoe, etc.)");
        AnsiConsole.MarkupLine("  --max-ping <ms>      Filter by maximum latency");
        AnsiConsole.MarkupLine("  --country <CC>       Filter by country code — comma-separated for multiple (e.g. DE,NL,FI)");
        AnsiConsole.MarkupLine("  --top <N>            How many results to return (default: 20)");
        AnsiConsole.MarkupLine("  --from <path|url>    Recommend providers based on a list of IPs (file path or HTTP URL)");
        AnsiConsole.MarkupLine("  --sort <field>       Sort by: score (default), coverage, latency, rpki, size, peering, upstream");
        AnsiConsole.MarkupLine("  --preset <name>      Scoring preset: balanced (default), performance, security");
        AnsiConsole.MarkupLine("  --trace-to <ip>      Run traceroute to IP and mark providers seen in the route");
        Console.WriteLine();
        AnsiConsole.MarkupLine("[yellow]Data:[/]");
        AnsiConsole.MarkupLine("  update               Download / refresh data files with progress (run after install; auto on first run)");
        Console.WriteLine();
        AnsiConsole.MarkupLine("[yellow]Configure:[/]");
        AnsiConsole.MarkupLine("  --set-key peeringdb=KEY      Save PeeringDB API key (free at peeringdb.com — fixes rate limits on -r)");
        AnsiConsole.MarkupLine("  --set-key abuseipdb=KEY      Save AbuseIPDB API key (free at abuseipdb.com)");
        AnsiConsole.MarkupLine("  --set-key greynoise=KEY      Save GreyNoise API key (free at greynoise.io)");
        AnsiConsole.MarkupLine("  --unset-key <service>        Remove a saved API key");
        AnsiConsole.MarkupLine("  --list-keys                  Show all configured API keys");
        Console.WriteLine();
        AnsiConsole.MarkupLine("[yellow]Inline keys (not saved, override config for this run):[/]");
        AnsiConsole.MarkupLine("  --peeringdb-key <key>        Use PeeringDB key without saving");
        AnsiConsole.MarkupLine("  --abuseipdb-key <key>        Use AbuseIPDB key without saving");
        AnsiConsole.MarkupLine("  --greynoise-key <key>        Use GreyNoise key without saving");
    }

    public static void PrintVersion()
    {
        var asm     = System.Reflection.Assembly.GetExecutingAssembly();
        var infoVer = System.Reflection.CustomAttributeExtensions
                         .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(asm)
                         ?.InformationalVersion;
        // Trim MSBuild metadata such as "+abc1234" from a version like "1.2.0-alpha.0+abc1234".
        if (infoVer != null)
        {
            int plus = infoVer.IndexOf('+');
            if (plus >= 0) infoVer = infoVer[..plus];
        }
        string ver = infoVer ?? asm.GetName().Version?.ToString(3) ?? "unknown";
        AnsiConsole.MarkupLine($"[bold]rover[/] v{ver}");
    }
}
