namespace SubnetSearch.Cli.Rendering;

public static class DomainRenderer
{
    public static void PrintDomainResult(DomainClassificationResult result)
    {
        AnsiConsole.MarkupLine($"[bold]Domain:[/]            {Markup.Escape(result.Domain)}");
        AnsiConsole.MarkupLine($"  [bold]IP addresses:[/]    {string.Join(", ", result.ResolvedIpAddresses.Select(Markup.Escape))}");
        AnsiConsole.MarkupLine($"  [bold]Reverse DNS:[/]     {Markup.Escape(result.ReverseDns ?? "N/A")}");
        AnsiConsole.MarkupLine($"  [bold]Registrar:[/]       {Markup.Escape(result.DomainRegistrar ?? "N/A")}");
        AnsiConsole.MarkupLine($"  [bold]Hosting provider:[/] {Markup.Escape(result.DomainHostingProvider ?? "N/A")}");
        if (!string.IsNullOrWhiteSpace(result.DomainServiceType))
            AnsiConsole.MarkupLine($"  [bold]Domain service:[/]  [yellow]{Markup.Escape(result.DomainServiceType)}[/]");
        if (result.RegistrationDate.HasValue)
            AnsiConsole.MarkupLine($"  [bold]Registered:[/]     {result.RegistrationDate.Value:yyyy-MM-dd}");
        if (result.ExpirationDate.HasValue)
            AnsiConsole.MarkupLine($"  [bold]Expires:[/]        {result.ExpirationDate.Value:yyyy-MM-dd}");
        if (result.NameServers?.Count > 0)
            AnsiConsole.MarkupLine($"  [bold]Nameservers:[/]    {string.Join(", ", result.NameServers.Select(Markup.Escape))}");
        if (!string.IsNullOrWhiteSpace(result.WhoisStatus))
            AnsiConsole.MarkupLine($"  [bold]WHOIS status:[/]   {Markup.Escape(result.WhoisStatus)}");

        // Print the HTTP and TLS fingerprint separately instead of creating a fake classification result.
        if (result.Http != null)
            ClassificationRenderer.PrintHttpBlock(result.Http);

        Console.WriteLine();

        // Deduplicate IP results by ASN to avoid showing the same hosting block twice.
        var seen = new HashSet<uint?>();
        foreach (var ipRes in result.IpResults)
        {
            if (!seen.Add(ipRes.Asn)) continue;
            ClassificationRenderer.PrintResult("", ipRes);
        }
    }
}
