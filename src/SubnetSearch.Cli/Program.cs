using Spectre.Console;
using SubnetSearch.Classification;
using SubnetSearch.Network.Recommend;
using SubnetSearch.Cli;
using SubnetSearch.Cli.Commands;

// ================== VERSION / HELP (immediate exit, no downloads) ==================
if (args.Contains("--version") || args.Contains("-v"))
{
    HelpText.PrintVersion();
    return 0;
}
if (args.Contains("--help") || args.Contains("-h"))
{
    HelpText.PrintVersion();
    Console.WriteLine();
    HelpText.ShowHelp();
    return 0;
}

// ================== CONFIG COMMANDS (before any data download) ==================
var appConfig = ConfigManager.Load();

if (args.Contains("--list-keys"))
{
    ConfigManager.ListKeys();
    return 0;
}
if (args.Contains("--unset-key"))
{
    var idx = Array.IndexOf(args, "--unset-key");
    if (idx + 1 >= args.Length)
    {
        AnsiConsole.MarkupLine("[red]Usage: --unset-key <service>  e.g. --unset-key abuseipdb[/]");
        return 1;
    }
    ConfigManager.UnsetKey(args[idx + 1]);
    return 0;
}
if (args.Contains("--set-key"))
{
    var idx = Array.IndexOf(args, "--set-key");
    if (idx + 1 >= args.Length)
    {
        AnsiConsole.MarkupLine("[red]Usage: --set-key <service>=<value>  e.g. --set-key abuseipdb=YOUR_KEY[/]");
        return 1;
    }
    var pair = args[idx + 1];
    var eq   = pair.IndexOf('=');
    if (eq < 0)
    {
        AnsiConsole.MarkupLine("[red]Format must be: --set-key <service>=<value>[/]");
        return 1;
    }
    ConfigManager.SetKey(pair[..eq], pair[(eq + 1)..]);
    return 0;
}

// ================== ARG VALIDATION (before downloads) ==================
if (args.Length > 0)
{
    var (valid, error) = ArgsParser.Validate(args);
    if (!valid)
    {
        AnsiConsole.MarkupLine($"[red]Error:[/] {Markup.Escape(error!)}");
        Console.WriteLine();
        HelpText.ShowHelp();
        return 1;
    }
}

// ================== CANCELLATION (Ctrl+C) ==================
// Registered BEFORE data download so Ctrl+C during the download cancels cleanly.
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

// ================== BOOTSTRAP (download + config + peeringDb client) ==================
var ctx = await AppBootstrap.InitializeAsync(args, appConfig, cts);
if (ctx is null)
{
    // Cancelled during download (Ctrl+C) — preserve the exit-130 semantics.
    AnsiConsole.MarkupLine("[yellow]Cancelled.[/]");
    return 130;
}

// Router owns the peeringDbHttp lifecycle for the rest of the run (D-08).
using var peeringDbHttp = ctx.PeeringDbHttp;

// ================== EMPTY-ARGS DEMO ==================
if (args.Length == 0)
{
    HelpText.ShowHelp();
    // Empty-args demo is a separate routing path — it does NOT set up the parallel
    // PeeringDB status check (Pitfall 4). DemoCommand creates its own peeringDbHttp
    // internally and never touches ctx.PeeringDbHttp.
    await new DemoCommand(ctx).ExecuteAsync(cts.Token);
    return 0;
}

// `update` — единственная задача была провижининг данных (Visible-режим уже отработал
// в AppBootstrap). Дальше запускать нечего — выходим до PeeringDB-инициализации и роутинга.
if (args[0].Equals("update", StringComparison.OrdinalIgnoreCase))
    return 0;

string mode     = args[0].ToLower();
string argument = args.Length > 1 ? args[1] : string.Empty;

// ================== INIT: PeeringDB check runs in parallel with main command ==================
AnsiConsole.Write("Initializing... ");
var peeringDbStatusTask = new PeeringDbWebsiteResolver(ctx.PeeringDbHttp).IsAvailableAsync();

try
{
    switch (mode)
    {
        case "-a":
            await new SingleIpCommand(ctx, argument).ExecuteAsync(cts.Token);
            break;
        case "-d":
            await new DomainCommand(ctx, argument).ExecuteAsync(cts.Token);
            break;
        case "-c":
            await new CidrCommand(ctx, argument).ExecuteAsync(cts.Token);
            break;
        case "-l":
            await new FileListCommand(ctx, argument).ExecuteAsync(cts.Token);
            break;
        case "-o":
            await new ProviderCommand(ctx, argument).ExecuteAsync(cts.Token);
            break;
        case "-r":
            int? maxPing = null;
            var mpIdx = Array.IndexOf(args, "--max-ping");
            if (mpIdx >= 0 && mpIdx + 1 < args.Length && int.TryParse(args[mpIdx + 1], out var mp))
                maxPing = mp;
            string? countryFilter = null;
            var ccIdx = Array.IndexOf(args, "--country");
            if (ccIdx >= 0 && ccIdx + 1 < args.Length)
                countryFilter = args[ccIdx + 1];
            int returnTop = 20;
            var topIdx = Array.IndexOf(args, "--top");
            if (topIdx >= 0 && topIdx + 1 < args.Length && int.TryParse(args[topIdx + 1], out var t))
                returnTop = t;
            string? typeFilter = ArgsParser.GetArgValue(args, "--type");
            if (typeFilter != null && ProviderFinder.ResolveInfoTypes(typeFilter) == null)
            {
                AnsiConsole.MarkupLine($"[red]Unknown --type value: '{Markup.Escape(typeFilter)}'[/]");
                AnsiConsole.MarkupLine($"[yellow]Valid values:[/]  {ProviderFinder.ValidTypeValues}");
                return 1;
            }
            string? sortBy     = ArgsParser.GetArgValue(args, "--sort");
            string? traceTo    = ArgsParser.GetArgValue(args, "--trace-to");
            string? fromSource = ArgsParser.GetArgValue(args, "--from");
            string? preset     = ArgsParser.GetArgValue(args, "--preset");
            // Treat argument as region only if it's not a flag (doesn't start with --)
            string? region = !string.IsNullOrWhiteSpace(argument) && !argument.StartsWith("--")
                ? argument : null;
            await new RecommendCommand(ctx, region, maxPing, countryFilter, returnTop, typeFilter,
                sortBy, traceTo, fromSource, preset).ExecuteAsync(cts.Token);
            break;
        default:
            AnsiConsole.MarkupLine($"[red]Unknown mode: {Markup.Escape(mode)}[/]");
            HelpText.ShowHelp();
            return 1;
    }
}
catch (OperationCanceledException) when (cts.Token.IsCancellationRequested)
{
    AnsiConsole.MarkupLine("[yellow]Cancelled.[/]");
    Environment.Exit(130);
}
catch (Exception ex)
{
    AnsiConsole.MarkupLine($"[red]Error: {Markup.Escape(ex.Message)}[/]");
    Environment.Exit(1);
}

var status = await peeringDbStatusTask;
Console.WriteLine();
if (status.IsAvailable)
    AnsiConsole.MarkupLine($"[dim]PeeringDB: [green]✓ available[/] (HTTP {status.HttpStatusCode}, {status.Elapsed.TotalSeconds:F1}s)[/]");
else
    AnsiConsole.MarkupLine($"[dim]PeeringDB: [yellow]✗ unavailable[/] — website enrichment disabled[/]");

Console.WriteLine("\nDone.");
return 0;
