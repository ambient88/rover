using Spectre.Console;
using SubnetSearch.Network.Recommend;
using SubnetSearch.Cli;
using SubnetSearch.Cli.Commands;

// Version and help exit without downloading data.
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

// Configuration commands run before data downloads.
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
    var eq = pair.IndexOf('=');
    if (eq < 0)
    {
        AnsiConsole.MarkupLine("[red]Format must be: --set-key <service>=<value>[/]");
        return 1;
    }
    ConfigManager.SetKey(pair[..eq], pair[(eq + 1)..]);
    return 0;
}

// Argument validation runs before downloads.
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

// Register cancellation before downloading so Ctrl+C stops the operation cleanly.
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

// Maintenance commands run before data provisioning: uninstalling or updating the
// binary must never trigger a data download first.
string firstMode = args.Length > 0 ? args[0].ToLowerInvariant() : "";
if (firstMode == "self-update")
{
    try
    {
        return await SelfUpdateCommand.ExecuteAsync(cts.Token);
    }
    catch (OperationCanceledException) when (cts.IsCancellationRequested)
    {
        AnsiConsole.MarkupLine("[yellow]Cancelled.[/]");
        return 130;
    }
}
if (firstMode == "uninstall")
    return UninstallCommand.Execute(args);

// Bootstrap data, configuration, and the PeeringDB client.
var ctx = await AppBootstrap.InitializeAsync(args, appConfig, cts);
if (ctx is null)
{
    // Preserve exit code 130 when Ctrl+C cancels a download.
    AnsiConsole.MarkupLine("[yellow]Cancelled.[/]");
    return 130;
}

// Router owns the peeringDbHttp lifecycle for the rest of the run (D-08).
using var peeringDbHttp = ctx.PeeringDbHttp;

// Show the demo when no arguments are supplied.
if (args.Length == 0)
{
    HelpText.ShowHelp();
    // The empty-arguments demo uses a separate route and does not initialize the parallel
    // PeeringDB status check. DemoCommand creates its own PeeringDB client
    // internally and never touches ctx.PeeringDbHttp.
    await new DemoCommand(ctx).ExecuteAsync(cts.Token);
    return 0;
}

// `update` had one job, provisioning data (the Visible mode already ran in
// AppBootstrap). Nothing else to do, so exit before PeeringDB init and routing.
int modeIndex = ArgsParser.FindModeIndex(args);
string mode = modeIndex >= 0 ? args[modeIndex].ToLowerInvariant() : args[0].ToLowerInvariant();
if (mode == "update")
{
    // One-line nudge when a newer release exists. Fail-soft: an offline or
    // rate-limited GitHub API (or Ctrl+C during the check) must never affect
    // the data update's outcome.
    try
    {
        if (!cts.IsCancellationRequested)
        {
            using var releaseHttp = new HttpClient();
            var latest = await new SubnetSearch.Data.GitHubReleaseClient(releaseHttp)
                .GetLatestAsync(cts.Token);
            if (latest != null && SubnetSearch.Data.GitHubReleaseClient.IsNewer(latest.Version, HelpText.CurrentVersion))
                AnsiConsole.MarkupLine(
                    $"[yellow]rover v{Markup.Escape(latest.Version)} is available[/] " +
                    $"(current: v{Markup.Escape(HelpText.CurrentVersion)}). Run [bold]rover self-update[/] to install.");
        }
    }
    catch (OperationCanceledException) { }
    return 0;
}

string argument = modeIndex >= 0 && modeIndex + 1 < args.Length
    ? args[modeIndex + 1]
    : string.Empty;

AnsiConsole.Write("Initializing... ");

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
            string? sortBy = ArgsParser.GetArgValue(args, "--sort");
            string? traceTo = ArgsParser.GetArgValue(args, "--trace-to");
            string? fromSource = ArgsParser.GetArgValue(args, "--from");
            string? preset = ArgsParser.GetArgValue(args, "--preset");
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

Console.WriteLine("\nDone.");
return 0;
