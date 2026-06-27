using Spectre.Console;
using SubnetSearch.Classification;
using SubnetSearch.Network;
using SubnetSearch.Network.Http;
using SubnetSearch.Network.Recommend;
using SubnetSearch.Network.Reputation;
using SubnetSearch.Cli;
using SubnetSearch.Cli.Config;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Models.Data;
using SubnetSearch.Core.Models.Network;
using System.Net;

// ================== VERSION / HELP (immediate exit, no downloads) ==================
if (args.Contains("--version") || args.Contains("-v"))
{
    PrintVersion();
    return 0;
}
if (args.Contains("--help") || args.Contains("-h"))
{
    PrintVersion();
    Console.WriteLine();
    ShowHelp();
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
    var (valid, error) = ValidateArgs(args);
    if (!valid)
    {
        AnsiConsole.MarkupLine($"[red]Error:[/] {Markup.Escape(error!)}");
        Console.WriteLine();
        ShowHelp();
        return 1;
    }
}

// ================== CANCELLATION (Ctrl+C) ==================
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

// ================== SETUP ==================
string dataDir = DefaultDataPath.GetDefaultDataDirectory();

var downloadOptions = new DownloadOptions
{
    MaxRetries            = 3,
    RetryDelayMilliseconds = 2000,
    TimeoutSeconds        = 600,   // 10 min — large files (as.json ~65 MB)
    UseResume             = true,
    PartialDownloadsDir   = dataDir  // persistent cross-run resume
};

// Bind downloads to the physical interface to bypass VPN routing.
// Falls back to the standard client if no physical interface is detected.
var downloadBypass = NetworkInterfaceHelper.CreateBypassVpnHttpClient(
    TimeSpan.FromSeconds(downloadOptions.TimeoutSeconds));
if (downloadBypass != null)
    downloadBypass.DefaultRequestHeaders.UserAgent.ParseAdd("SubnetSearch/1.0");
using var downloadHttp = downloadBypass ?? DownloadManagerFactory.CreateHttpClient(downloadOptions);

var downloader      = DownloadManagerFactory.CreateDownloader(downloadHttp);
var storage         = DownloadManagerFactory.CreateStorage(dataDir);
var files           = DownloadManagerFactory.GetDefaultFiles();
var metaStore       = new SubnetSearch.Data.FileMetadataStore(dataDir);
var downloadManager = new DownloadManager(downloader, storage, files, metaStore);

// ================== DATA FILES ==================
await AnsiConsole.Progress()
    .AutoClear(false)
    .Columns(new ProgressColumn[]
    {
        new TaskDescriptionColumn(),
        new ProgressBarColumn(),
        new DownloadedColumn(),
        new TransferSpeedColumn(),
        new RemainingTimeColumn()
    })
    .StartAsync(async ctx =>
    {
        var spectreTaskMap = files.ToDictionary(
            f => f.FileName,
            f => ctx.AddTask($"[green]{Markup.Escape(f.FileName)}[/]", maxValue: 1, autoStart: false));

        var results = await downloadManager.DownloadAllDetailedAsync(
            downloadOptions,
            progressFactory: file =>
            {
                var t = spectreTaskMap[file.FileName];
                t.StartTask();
                return new Progress<DownloadProgress>(p =>
                {
                    if (p.TotalBytes.HasValue && t.MaxValue != p.TotalBytes.Value)
                        t.MaxValue = p.TotalBytes.Value;
                    t.Value = p.BytesDownloaded;
                });
            },
            maxDegreeOfParallelism: 3,
            cancellationToken: cts.Token);

        foreach (var r in results)
        {
            var t = spectreTaskMap[r.FileName];
            if (r.Skipped)
            {
                t.Description = $"[gray]{Markup.Escape(r.FileName)} (up to date)[/]";
                t.Value = 100;
            }
            else if (r.NotModified)
            {
                t.Description = $"[gray]{Markup.Escape(r.FileName)} (not modified)[/]";
                t.Value = 100;
            }
            else if (r.Stale)
            {
                t.Description = $"[yellow]{Markup.Escape(r.FileName)} (stale — update failed: {Markup.Escape(r.ErrorMessage ?? "")})[/]";
                t.Value = 100;
            }
            else if (!r.Success)
            {
                t.Description = $"[red]{Markup.Escape(r.FileName)} (error: {Markup.Escape(r.ErrorMessage ?? "")})[/]";
            }
            else
            {
                t.Description = $"[green]{Markup.Escape(r.FileName)} (updated)[/]";
                t.Value = t.MaxValue;
            }
            t.StopTask();
        }
    });

Console.WriteLine("\nDownload complete.\n");

// ================== ARGUMENTS ==================
bool forceWhois = args.Contains("--whois");

// Inline keys override saved config for this run only (not persisted).
var inlinePeeringDb = GetArgValue(args, "--peeringdb-key");
var inlineAbuseIpDb = GetArgValue(args, "--abuseipdb-key");
var inlineGreyNoise = GetArgValue(args, "--greynoise-key");
if (inlinePeeringDb != null) ConfigManager.ApplyInline(appConfig, "peeringdb", inlinePeeringDb);
if (inlineAbuseIpDb != null) ConfigManager.ApplyInline(appConfig, "abuseipdb", inlineAbuseIpDb);
if (inlineGreyNoise != null) ConfigManager.ApplyInline(appConfig, "greynoise",  inlineGreyNoise);

if (args.Length == 0)
{
    ShowHelp();
    await RunDemo(dataDir, forceWhois);
    return 0;
}

string mode     = args[0].ToLower();
string argument = args.Length > 1 ? args[1] : string.Empty;

// ================== INIT: PeeringDB check runs in parallel with main command ==================
// Bypass VPN by binding to the physical network interface.
// Falls back to default HttpClient if no physical interface is detected.
var bypassClient = NetworkInterfaceHelper.CreateBypassVpnHttpClient();
using var peeringDbHttp = ClassifierFactory.CreatePeeringDbHttpClient(bypassClient, appConfig.PeeringDbKey);
var peeringDbResolver   = new PeeringDbWebsiteResolver(peeringDbHttp);

AnsiConsole.Write("Initializing... ");
var peeringDbStatusTask = peeringDbResolver.IsAvailableAsync();

try
{
    switch (mode)
    {
        case "-a":
            await HandleSingleIp(dataDir, argument, forceWhois, peeringDbHttp);
            break;
        case "-d":
            await HandleDomain(dataDir, argument, peeringDbHttp);
            break;
        case "-c":
            await HandleCidr(dataDir, argument, forceWhois, peeringDbHttp);
            break;
        case "-l":
            await HandleFileList(dataDir, argument, forceWhois, peeringDbHttp);
            break;
        case "-o":
            await HandleProvider(dataDir, argument, peeringDbHttp);
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
            string? typeFilter = GetArgValue(args, "--type");
            if (typeFilter != null && ProviderFinder.ResolveInfoTypes(typeFilter) == null)
            {
                AnsiConsole.MarkupLine($"[red]Unknown --type value: '{Markup.Escape(typeFilter)}'[/]");
                AnsiConsole.MarkupLine($"[yellow]Valid values:[/]  {ProviderFinder.ValidTypeValues}");
                return 1;
            }
            string? sortBy     = GetArgValue(args, "--sort");
            string? traceTo    = GetArgValue(args, "--trace-to");
            string? fromSource = GetArgValue(args, "--from");
            string? preset     = GetArgValue(args, "--preset");
            // Treat argument as region only if it's not a flag (doesn't start with --)
            string? region = !string.IsNullOrWhiteSpace(argument) && !argument.StartsWith("--")
                ? argument : null;
            await HandleRecommend(dataDir, region, maxPing, countryFilter, returnTop, typeFilter,
                sortBy, traceTo, fromSource, preset, peeringDbHttp, appConfig);
            break;
        default:
            AnsiConsole.MarkupLine($"[red]Unknown mode: {Markup.Escape(mode)}[/]");
            ShowHelp();
            break;
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

// ================== COMMAND HANDLERS ==================
static void ShowHelp()
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
    AnsiConsole.MarkupLine("                         server          — all server rental: VPS, dedicated, cloud  [[aliases: hosting, vps, dedicated, cloud]]");
    AnsiConsole.MarkupLine("                         cdn / content   — CDN and content networks");
    AnsiConsole.MarkupLine("                         nsp / isp / transit  — Network service providers");
    AnsiConsole.MarkupLine("  --max-ping <ms>      Filter by maximum latency");
    AnsiConsole.MarkupLine("  --country <CC>       Filter by country code — comma-separated for multiple (e.g. DE,NL,FI)");
    AnsiConsole.MarkupLine("  --top <N>            How many results to return (default: 20)");
    AnsiConsole.MarkupLine("  --from <path|url>    Recommend providers based on a list of IPs (file path or HTTP URL)");
    AnsiConsole.MarkupLine("  --sort <field>       Sort by: score (default), coverage, latency, rpki, size, peering, upstream");
    AnsiConsole.MarkupLine("  --preset <name>      Scoring preset: balanced (default), performance, security");
    AnsiConsole.MarkupLine("  --trace-to <ip>      Run traceroute to IP and mark providers seen in the route");
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

static async Task HandleProvider(string dataDir, string query, HttpClient peeringDbHttp)
{
    if (string.IsNullOrWhiteSpace(query))
        throw new ArgumentException("Provide an ASN (e.g. AS213520 or 213520) or provider name.");

    AnsiConsole.MarkupLine($"[cyan]Looking up provider: {Markup.Escape(query)}[/]\n");

    // CLI wires Classification and Network together directly.
    var peeringDbRes = new PeeringDbWebsiteResolver(peeringDbHttp);
    var websiteRes   = new HostingWebsiteResolver([], [], peeringDbRes);
    var ripeClient   = new RipeStatClient(peeringDbHttp);
    var records      = await new Ip2AsnLoader().LoadAsync(Path.Combine(dataDir, "ip2asn-v4.tsv.gz"));
    var ipIndex      = new IpRangeIndex(records);
    var scanner      = new ProviderScanner(ripeClient, websiteRes, ipIndex);

    var result = await scanner.ScanAsync(query);

    if (result == null)
    {
        AnsiConsole.MarkupLine("[red]Provider not found.[/]");
        return;
    }

    PrintProviderResult(result);
}

static void PrintProviderResult(ProviderScanResult r)
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
        AnsiConsole.MarkupLine($"  [bold]Website:[/]       [link={r.Website}]{Markup.Escape(r.Website)}[/]");
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

static async Task HandleSingleIp(string dataDir, string ip, bool forceWhois, HttpClient peeringDbHttp)
{
    if (!IPAddress.TryParse(ip, out var parsedIp))
        throw new ArgumentException($"Invalid IP address: {ip}");
    if (parsedIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        throw new ArgumentException($"Only IPv4 addresses are supported: {ip}");

    var classifier = await ClassifierFactory.CreateAsync(dataDir, forceWhois, peeringDbHttp);

    // Classification and network tests run in parallel.
    var classifyTask   = classifier.ClassifyAsync(ip);
    var pingTask       = new PingService().PingAsync(ip);
    var tracerouteTask = new TracerouteService().TraceAsync(ip);
    var portsTask      = new PortScanner().ScanAsync(ip);
    var httpTask       = new HttpFingerprintService().FingerprintAsync(ip);

    await Task.WhenAll(classifyTask, pingTask, tracerouteTask, portsTask, httpTask);

    // Traceroute analysis: PTR resolution + proxy detection runs after hops are available.
    var traceAnalysis = await SubnetSearch.Network.TracerouteAnalyzer.AnalyzeAsync(
        tracerouteTask.Result, new SubnetSearch.Classification.DnsResolver());

    PrintResult(ip, classifyTask.Result, pingTask.Result, traceAnalysis, portsTask.Result, httpTask.Result);
}

static async Task HandleDomain(string dataDir, string domain, HttpClient peeringDbHttp)
{
    if (string.IsNullOrWhiteSpace(domain))
        throw new ArgumentException("Provide a domain name.");
    var domainClassifier = await ClassifierFactory.CreateDomainClassifierAsync(dataDir, peeringDbHttp);
    var classifyTask     = domainClassifier.ClassifyDomainAsync(domain);
    var httpTask         = new HttpFingerprintService().FingerprintAsync(domain);
    await Task.WhenAll(classifyTask, httpTask);
    PrintDomainResult(classifyTask.Result with { Http = httpTask.Result });
}

static async Task HandleCidr(string dataDir, string cidr, bool forceWhois, HttpClient peeringDbHttp)
{
    if (!TryParseCidr(cidr, out uint start, out uint end))
        throw new ArgumentException($"Invalid CIDR: {cidr}");

    long totalIps = (long)end - start + 1;

    int warnThreshold = forceWhois ? 50 : 256;
    if (totalIps > warnThreshold)
    {
        if (forceWhois)
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
            return;
    }

    var batchClassifier = await ClassifierFactory.CreateBatchClassifierAsync(dataDir, forceWhois, peeringDbHttp);

    // Guard against ranges too large to hold in memory.
    if (totalIps > 1_000_000)
        throw new ArgumentException($"CIDR range too large ({totalIps:N0} addresses). Use -l with a pre-generated file.");

    var ips = new List<string>((int)totalIps);
    // Iterate without post-increment past uint.MaxValue: add last element separately.
    for (uint current = start; current != end; current++)
        ips.Add(UintToIp(current));
    ips.Add(UintToIp(end));

    IReadOnlyList<ClassificationResult> results = [];
    await AnsiConsole.Progress()
        .AutoClear(false)
        .StartAsync(async ctx =>
        {
            var task = ctx.AddTask("[green]Scanning CIDR[/]", maxValue: totalIps);
            results = await batchClassifier.ClassifyIpsAsync(ips,
                new Progress<BatchProgress>(p => task.Value = p.ProcessedItems));
            task.StopTask();
        });

    Console.WriteLine();
    int hostingCount = results.Count(r => r.IsHosting);
    double percent   = totalIps > 0 ? (double)hostingCount / totalIps * 100 : 0;
    AnsiConsole.MarkupLine($"Hosting addresses: [green]{hostingCount}[/] of [blue]{totalIps}[/] ({percent:F1}%)");
    PrintTable(ips.Zip(results).Select(t => (t.First, t.Second)).ToList());
}

static async Task HandleFileList(string dataDir, string filePath, bool forceWhois, HttpClient peeringDbHttp)
{
    if (!File.Exists(filePath))
        throw new FileNotFoundException($"File not found: {filePath}");

    const long MaxFileSizeBytes = 50L * 1024 * 1024; // 50 MB
    var fileInfo = new FileInfo(filePath);
    if (fileInfo.Length > MaxFileSizeBytes)
        throw new InvalidOperationException(
            $"File too large: {fileInfo.Length / 1024 / 1024} MB (max 50 MB). Split the file and run in batches.");

    var lines = await File.ReadAllLinesAsync(filePath);
    var items = lines.Where(l => !string.IsNullOrWhiteSpace(l)).Select(l => l.Trim()).ToList();

    if (items.Count == 0)
        throw new InvalidOperationException("File is empty.");

    var batchClassifier = await ClassifierFactory.CreateBatchClassifierAsync(dataDir, forceWhois, peeringDbHttp);
    var ips     = new List<string>();
    var domains = new List<string>();

    foreach (var item in items)
    {
        if (IPAddress.TryParse(item, out _))
            ips.Add(item);
        else if (Uri.CheckHostName(item) == UriHostNameType.Dns)
            domains.Add(item);
        else
            AnsiConsole.MarkupLine($"[yellow]Skipped: {Markup.Escape(item)} (not an IP or domain)[/]");
    }

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
                    new Progress<BatchProgress>(p => { if (ipTask != null) ipTask.Value = p.ProcessedItems; }))
                : Task.FromResult<IReadOnlyList<ClassificationResult>>([]);

            var classifyDomains = domains.Count > 0
                ? batchClassifier.ClassifyDomainsAsync(domains,
                    new Progress<BatchProgress>(p => { if (domainTask != null) domainTask.Value = p.ProcessedItems; }))
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
                r.Website != null ? $"[link={r.Website}]{Markup.Escape(r.Website)}[/]" : "N/A"
            );
        }
        AnsiConsole.Write(ipTable);
    }

    if (domains.Count > 0)
    {
        AnsiConsole.MarkupLine("\n[bold]Domain results:[/]");
        foreach (var dr in domainResults)
            PrintDomainResult(dr);
    }
}

static async Task RunDemo(string dataDir, bool forceWhois)
{
    using var peeringDbHttp = ClassifierFactory.CreatePeeringDbHttpClient();
    var classifier = await ClassifierFactory.CreateAsync(dataDir, forceWhois, peeringDbHttp);
    const string testIp = "8.8.8.8";
    AnsiConsole.MarkupLine($"[cyan]Demo check IP: {Markup.Escape(testIp)}[/]");
    var result = await classifier.ClassifyAsync(testIp);
    PrintResult(testIp, result);
}

// ================== OUTPUT ==================
static void PrintResult(
    string ip,
    ClassificationResult result,
    PingStats? ping = null,
    TracerouteAnalysis? traceroute = null,
    IReadOnlyList<int>? openPorts = null,
    HttpFingerprintResult? http = null)
{
    if (!string.IsNullOrEmpty(ip))
        AnsiConsole.MarkupLine($"[cyan]IP: {Markup.Escape(ip)}[/]");

    // When querying a CDN IP directly (-a), show node type — no "hidden" warning.
    // http != null means HTTP responded → Tunnel; http == null → WARP (no service running).
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
        AnsiConsole.MarkupLine($"  [bold]Website:[/]      [link={result.Website}]{Markup.Escape(result.Website)}[/]");
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

        // Hidden route block: shown when proxy/CDN is the last visible hop + trailing timeouts.
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

static void PrintHttpBlock(HttpFingerprintResult http)
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

static void PrintDomainResult(DomainClassificationResult result)
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

    // HTTP/TLS fingerprint — printed separately, not via a fake ClassificationResult.
    if (result.Http != null)
        PrintHttpBlock(result.Http);

    Console.WriteLine();

    // Deduplicate IP results by ASN — no need to show identical hosting blocks twice.
    var seen = new HashSet<uint?>();
    foreach (var ipRes in result.IpResults)
    {
        if (!seen.Add(ipRes.Asn)) continue;
        PrintResult("", ipRes);
    }
}

static async Task HandleRecommend(
    string dataDir, string? region, int? maxPingMs,
    string? countryFilter, int returnTop, string? typeFilter,
    string? sortBy, string? traceTo, string? fromSource, string? preset,
    HttpClient peeringDbHttp, AppConfig config)
{
    bool isGlobal  = string.IsNullOrWhiteSpace(region);
    var infoTypes  = ProviderFinder.ResolveInfoTypes(typeFilter); // null = no filter (all types)

    // Parse comma-separated country codes: "DE,NL,FI" → ["DE","NL","FI"]
    string[]? countryCodes = countryFilter?
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(c => c.ToUpperInvariant())
        .ToArray();
    string? countryDisplay = countryCodes?.Length > 0 ? string.Join(",", countryCodes) : null;

    string title   = isGlobal
        ? (countryDisplay != null ? countryDisplay : "Worldwide")
        : region!;

    AnsiConsole.MarkupLine($"[cyan]Finding providers: {Markup.Escape(title)}[/]");
    if (typeFilter != null)
        AnsiConsole.MarkupLine($"[dim]Type: {Markup.Escape(typeFilter)} → {Markup.Escape(string.Join(", ", infoTypes ?? []))}[/]");
    if (maxPingMs.HasValue)
        AnsiConsole.MarkupLine($"[dim]Max ping: {maxPingMs.Value} ms[/]");
    AnsiConsole.MarkupLine($"[dim]Top: {returnTop}[/]");
    if (preset != null)
        AnsiConsole.MarkupLine($"[dim]Preset: {Markup.Escape(preset)}[/]");
    if (sortBy?.ToLowerInvariant() == "coverage" && string.IsNullOrWhiteSpace(fromSource))
        AnsiConsole.MarkupLine("[yellow]Note: --sort coverage requires --from; falling back to score.[/]");
    Console.WriteLine();

    var ripeCache  = await RipeStatCache.LoadAsync(dataDir);
    var ripeClient = new RipeStatClient(peeringDbHttp, ripeCache);
    var spamhaus   = new SpamhausDropClient(peeringDbHttp);
    var ipapiIs    = new IpapiIsClient(peeringDbHttp);
    var abuseIpDb  = config.AbuseIpDbKey != null ? new AbuseIpDbClient(peeringDbHttp, config.AbuseIpDbKey) : null;
    var greyNoise  = config.GreyNoiseKey  != null ? new GreyNoiseClient(peeringDbHttp, config.GreyNoiseKey)  : null;

    var ipsumData  = await new IpsumLoader().LoadAsync(Path.Combine(dataDir, "ipsum.txt"));
    var ipsum      = new IpsumReputationChecker(ipsumData);
    var exclusions = await AsnExclusions.LoadAsync(Path.Combine(dataDir, "asn-exclusions.json"));

    var ip2asnRecords = await new Ip2AsnLoader().LoadAsync(Path.Combine(dataDir, "ip2asn-v4.tsv.gz"));
    var recoIpIndex   = new IpRangeIndex(ip2asnRecords);

    var bgpView    = new BgpViewClient(peeringDbHttp);
    var finder     = new ProviderFinder(peeringDbHttp, ripeClient, ipapiIs, exclusions, bgpView);
    var pingSvc    = new PingService();
    var scorer     = new ProviderScorer(spamhaus, ipapiIs, ipsum, pingSvc, abuseIpDb, greyNoise, recoIpIndex);
    var indexCache = new ProviderIndexCache(dataDir);

    IReadOnlyList<ProviderRecommendation> results = [];

    int diagnosticCandidates = 0;
    int diagnosticAfterRipe  = 0;
    Dictionary<string, int>? diagnosticPerType = null;
    IReadOnlyList<string> diagnosticErrors = [];
    int diagnosticPreEnrich = 0;

    int totalListIps = 0;
    Dictionary<uint, int>? coverageMap = null;

    // --from: build coverage map independently, then run the same global search as always.
    // Coverage is applied as an annotation after scoring — not a separate search pipeline.
    IReadOnlyList<(uint Asn, int Count)> fromAsnList = [];
    if (!string.IsNullOrWhiteSpace(fromSource))
    {
        try
        {
            var text = await IpListAnalyzer.ReadSourceAsync(fromSource, peeringDbHttp);
            var ips  = IpListAnalyzer.ExtractIps(text);
            if (ips.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]--from: no IPv4 addresses found in the source.[/]");
            }
            else
            {
                fromAsnList  = IpListAnalyzer.AggregateByAsn(ips, recoIpIndex);
                totalListIps = ips.Count;
                coverageMap  = fromAsnList.ToDictionary(a => a.Asn, a => a.Count);
                AnsiConsole.MarkupLine(
                    $"[dim]--from: {ips.Count} IPs → {fromAsnList.Count} ASNs (coverage map ready)[/]");
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[yellow]--from: could not load source — {Markup.Escape(ex.Message)}[/]");
        }
    }

    bool needsHostingFilter = ProviderFinder.ShouldExcludeCdn(typeFilter);
    IReadOnlyList<(uint Asn, int Count)>? localHostingAsns = null;

    await AnsiConsole.Status()
        .StartAsync("Searching...", async ctx =>
        {
            IReadOnlyList<ProviderCandidate> candidates;

            if (isGlobal && needsHostingFilter)
            {
                // --type server: single bulk PeeringDB request + local whitelist.
                //
                // BULK PeeringDB fetch (3 requests: Content/NSP/Hosting) with pre-filter:
                //   - Local whitelist ASNs → pass without ipapi.is call (confirmed hosting files).
                //   - All others → must have ipapi.is type "hosting" or "cloud".
                //   Rejects: Disney, TELE2, Sony, Meta, Cisco (isp/cdn/null → rejected).
                //
                // SUPPLEMENT: local ASNs not in PeeringDB's top-N → RIPE Stat fallback (up to 40).
                ctx.Status("Loading confirmed hosting providers from local databases...");
                localHostingAsns = await GetLocalHostingAsnsAsync(dataDir);
                var localWhitelist = new HashSet<uint>(localHostingAsns.Select(a => a.Asn));

                ctx.Status("Fetching providers from PeeringDB (3 bulk requests)...");
                candidates = [.. await finder.FindGlobalAsync(
                    countryCodes, topN: Math.Max(returnTop * 15, 1000), infoTypes: infoTypes,
                    excludeCdn: true, localHostingWhitelist: localWhitelist,
                    onPreEnrichment: (perType, errors, total) =>
                    {
                        diagnosticPerType   = perType;
                        diagnosticErrors    = errors;
                        diagnosticPreEnrich = total;
                    })];

                // Supplement: local ASNs missed by the top-N bulk result.
                var foundAsns = new HashSet<uint>(candidates.Select(c => c.Asn));
                var missing   = localHostingAsns
                    .Where(a => !foundAsns.Contains(a.Asn))
                    .Take(Math.Max(returnTop, 40))
                    .ToList();
                if (missing.Count > 0)
                {
                    ctx.Status($"Supplementing {missing.Count} local providers via RIPE Stat...");
                    var extra = await finder.FindByAsnListAsync(
                        missing, infoTypes: null, excludeCdn: needsHostingFilter,
                        localHostingWhitelist: localWhitelist);
                    candidates = [.. candidates.Concat(extra).DistinctBy(c => c.Asn)];
                }
            }
            else if (isGlobal)
            {
                // No hosting filter: PeeringDB global discovery + local file supplement.
                ctx.Status("Fetching all hosting networks from PeeringDB...");
                candidates = await finder.FindGlobalAsync(
                    countryCodes, topN: Math.Max(returnTop * 5, 300), infoTypes: infoTypes,
                    excludeCdn: false,
                    onPreEnrichment: (perType, errors, total) =>
                    {
                        diagnosticPerType   = perType;
                        diagnosticErrors    = errors;
                        diagnosticPreEnrich = total;
                    });

                // Supplement with local hosting DB only for unfiltered search (no --type).
                // For --type cdn or --type transit, hosting supplements add wrong provider types:
                // IaaS/datacenter ASNs would appear in CDN results, hosting in transit results.
                if (typeFilter == null)
                {
                    var globalAsns = new HashSet<uint>(candidates.Select(c => c.Asn));
                    ctx.Status("Supplementing from local datacenter databases...");
                    localHostingAsns = await GetLocalHostingAsnsAsync(dataDir);
                    var supplement = localHostingAsns.Where(a => !globalAsns.Contains(a.Asn)).Take(60).ToList();
                    if (supplement.Count > 0)
                    {
                        var extra = await finder.FindByAsnListAsync(supplement,
                            infoTypes: null, excludeCdn: false,
                            localHostingWhitelist: new HashSet<uint>(supplement.Select(a => a.Asn)));
                        candidates = [.. candidates.Concat(extra).DistinctBy(c => c.Asn)];
                    }
                }
            }
            else
            {
                ctx.Status($"Looking up IXPs in {region}...");
                candidates = await finder.FindByRegionAsync(region!, infoTypes: infoTypes,
                    excludeCdn: needsHostingFilter);
            }

            // --from: include ASNs from the user's IP list that weren't found by the main search.
            // Applies the same hosting filter as the main search — game companies (Valve),
            // media/CDN networks are still excluded when --type server is active.
            // The hosting filter uses balanced mode (null ipapi.is type + ≥1024 IPs passes),
            // so legitimate cloud providers like Yandex Cloud pass even when ipapi.is is down.
            if (fromAsnList.Count > 0)
            {
                var foundAsnsSet = new HashSet<uint>(candidates.Select(c => c.Asn));
                var missing = fromAsnList
                    .Where(a => !foundAsnsSet.Contains(a.Asn))
                    .Take(Math.Max(returnTop, 40))
                    .ToList();
                if (missing.Count > 0)
                {
                    ctx.Status($"Supplementing {missing.Count} providers from --from list...");
                    var forced = await finder.FindByAsnListAsync(
                        missing, infoTypes: null, excludeCdn: needsHostingFilter,
                        localHostingWhitelist: null);
                    candidates = [.. candidates.Concat(forced).DistinctBy(c => c.Asn)];
                }
            }

            // Country filter: PeeringDB bulk API does not return 'country', so we enrich
            // candidates from ip2asn (which has authoritative ASN→country mappings) before
            // filtering. Applied after all supplements to prevent bypass via --from or local DBs.
            if (countryCodes is { Length: > 0 })
            {
                if (candidates.Any(c => c.Country == null))
                {
                    ctx.Status("Resolving countries from ip2asn...");
                    var asnCountry = new Dictionary<uint, string>();
                    foreach (var r in ip2asnRecords)
                        asnCountry.TryAdd(r.Asn, r.Country);
                    candidates = [.. candidates.Select(c =>
                        c.Country == null && asnCountry.TryGetValue(c.Asn, out var cc) && !string.IsNullOrEmpty(cc)
                            ? c with { Country = cc }
                            : c)];
                }
                candidates = [.. candidates.Where(c =>
                    countryCodes.Contains(c.Country ?? "", StringComparer.OrdinalIgnoreCase))];
            }

            diagnosticAfterRipe  = candidates.Count;
            diagnosticCandidates = diagnosticAfterRipe;
            if (candidates.Count == 0) return;

            // RIPE Stat country-ASN supplement: recover hosting providers registered in the
            // target countries that PeeringDB's top-N bulk query did not include.
            // Only runs when --country is specified and the search is global (not region-based).
            if (countryCodes is { Length: > 0 } && isGlobal)
            {
                var foundAsns           = new HashSet<uint>(candidates.Select(c => c.Asn));
                var updatedCacheEntries = new Dictionary<string, IReadOnlyList<uint>>();
                var cacheData           = await indexCache.LoadAsync();
                var supplementPairs     = new List<(uint Asn, int Count)>();

                foreach (var cc in countryCodes)
                {
                    IReadOnlyList<uint> countryAsns;
                    if (cacheData != null && cacheData.TryGetValue(cc, out var hit))
                    {
                        countryAsns = hit;
                    }
                    else
                    {
                        ctx.Status($"Fetching ASN registry for {cc} from RIPE Stat...");
                        countryAsns = await ripeClient.GetCountryAsnsAsync(cc);
                        updatedCacheEntries[cc] = countryAsns;
                    }

                    supplementPairs.AddRange(
                        countryAsns
                            .Where(a => !foundAsns.Contains(a) && !exclusions.NonHostingAsns.Contains(a))
                            .Select(a => (a, 0)));
                }

                if (updatedCacheEntries.Count > 0)
                    await indexCache.SaveAsync(updatedCacheEntries);

                if (supplementPairs.Count > 0)
                {
                    localHostingAsns ??= await GetLocalHostingAsnsAsync(dataDir);
                    var localWhitelist2 = new HashSet<uint>(localHostingAsns.Select(a => a.Asn));

                    ctx.Status($"Filtering {supplementPairs.Count} country ASNs via ipapi.is...");
                    var hostingBag = new System.Collections.Concurrent.ConcurrentBag<(uint Asn, int Count)>();
                    await Parallel.ForEachAsync(supplementPairs,
                        new ParallelOptions { MaxDegreeOfParallelism = 15 },
                        async (pair, innerCt) =>
                        {
                            if (localWhitelist2.Contains(pair.Asn))
                            {
                                hostingBag.Add(pair);
                                return;
                            }
                            var info = await ipapiIs.GetAsnInfoAsync(pair.Asn, innerCt);
                            if (info.Type is "hosting" or "cloud")
                                hostingBag.Add(pair);
                        });

                    var filteredPairs = hostingBag.ToList();
                    if (filteredPairs.Count > 0)
                    {
                        // Build ASN→country map for tagging supplement results.
                        var asnToCountry = new Dictionary<uint, string>();
                        foreach (var cc in countryCodes)
                        {
                            if (cacheData != null && cacheData.TryGetValue(cc, out var c1))
                                foreach (var asn in c1) asnToCountry.TryAdd(asn, cc);
                            if (updatedCacheEntries.TryGetValue(cc, out var c2))
                                foreach (var asn in c2) asnToCountry.TryAdd(asn, cc);
                        }

                        ctx.Status($"Enriching {filteredPairs.Count} additional providers from country registry...");
                        var extra = await finder.FindByAsnListAsync(
                            filteredPairs, infoTypes: null, excludeCdn: needsHostingFilter,
                            localHostingWhitelist: localWhitelist2);

                        extra = [.. extra.Select(c =>
                            c.Country == null && asnToCountry.TryGetValue(c.Asn, out var countryTag)
                                ? c with { Country = countryTag } : c)];

                        candidates = [.. candidates.Concat(extra).DistinctBy(c => c.Asn)];
                        diagnosticAfterRipe  = candidates.Count;
                        diagnosticCandidates = diagnosticAfterRipe;
                    }
                }
            }

            // CDN pre-filter: apply before scoring so CDN providers (Cloudflare, Akamai, Fastly)
            // aren't crowded out of top-N by large IaaS providers (Microsoft, Amazon) whose IP pools
            // score higher on size metrics. PeeringDB "Content" mixes both types — filter IaaS first.
            if (typeFilter?.ToLowerInvariant() is "cdn" or "content")
            {
                localHostingAsns ??= await GetLocalHostingAsnsAsync(dataDir);
                var hostingSetCdn = new HashSet<uint>(localHostingAsns.Select(a => a.Asn));
                candidates = [.. candidates.Where(c =>
                    !hostingSetCdn.Contains(c.Asn) || exclusions.KnownCdnAsns.Contains(c.Asn))];
                diagnosticCandidates = candidates.Count;
                if (candidates.Count == 0) return;
            }

            ctx.Status($"Scoring {diagnosticCandidates} candidates (reputation + ping)...");
            int pingTopN = Math.Max(returnTop * 4, 80);
            var weights  = ScoringWeights.FromName(preset);

            // When --from is active: pin top-coverage providers so they survive the
            // prescore top-N cut in Phase 2 of scoring. Without this, providers with
            // many IPs from the list but few IXP peerings (e.g. Yandex Cloud: 535 IPs,
            // 11 peerings) are eliminated by the peering-weighted prescore before ping.
            IReadOnlySet<uint>? pinnedAsns = null;
            if (coverageMap != null)
            {
                var candidateAsns = new HashSet<uint>(candidates.Select(c => c.Asn));
                pinnedAsns = coverageMap
                    .Where(kv => candidateAsns.Contains(kv.Key))
                    .OrderByDescending(kv => kv.Value)
                    .Take(Math.Max(returnTop / 4, 5))
                    .Select(kv => kv.Key)
                    .ToHashSet();
            }

            results = await scorer.ScoreAsync(candidates, maxPingMs, returnTop, pingTopN,
                weights: weights, pinnedAsns: pinnedAsns);
        });

    int diagnosticAfterScoring = results.Count;

    if (diagnosticPerType != null)
    {
        var perTypeStr = string.Join(", ", diagnosticPerType.Select(p => $"{p.Key}: {p.Value}"));
        AnsiConsole.MarkupLine($"[dim]PeeringDB fetch: {perTypeStr}[/]");
        foreach (var err in diagnosticErrors)
            AnsiConsole.MarkupLine($"[yellow]  ! {Markup.Escape(err)}[/]");
        string cdnFilterNote = diagnosticCandidates != diagnosticAfterRipe
            ? $" → After CDN filter: {diagnosticCandidates}" : "";
        AnsiConsole.MarkupLine($"[dim]Pre-enrichment: {diagnosticPreEnrich} → After RIPE: {diagnosticAfterRipe}{cdnFilterNote} → After scoring: {diagnosticAfterScoring}[/]");
    }
    else
    {
        AnsiConsole.MarkupLine($"[dim]Candidates after enrichment: {diagnosticAfterRipe} | Results after scoring: {diagnosticAfterScoring}[/]");
    }

    if (results.Count == 0)
    {
        if (diagnosticCandidates == 0)
        {
            bool hasErrors   = diagnosticErrors.Count > 0;
            bool isRateLimit = hasErrors && diagnosticErrors.Any(e =>
                e.Contains("429", StringComparison.Ordinal) ||
                e.Contains("rate limit", StringComparison.OrdinalIgnoreCase));
            bool isTimeout   = hasErrors && diagnosticErrors.Any(e =>
                e.Contains("timed out", StringComparison.OrdinalIgnoreCase));

            if (isRateLimit)
            {
                AnsiConsole.MarkupLine("[yellow]PeeringDB rate limit is blocking results. Get a free API key to raise limits:[/]");
                AnsiConsole.MarkupLine("  subnetSearch --set-key peeringdb=YOUR_KEY  [dim](register free at peeringdb.com)[/]");
            }
            else if (isTimeout)
            {
                AnsiConsole.MarkupLine("[yellow]PeeringDB requests timed out — check your network connection or try again later.[/]");
                await CheckPeeringDbConnectivityAsync(peeringDbHttp);
            }
            else if (hasErrors)
            {
                AnsiConsole.MarkupLine("[yellow]PeeringDB fetch failed — see errors above.[/]");
                await CheckPeeringDbConnectivityAsync(peeringDbHttp);
            }
            else if (diagnosticPreEnrich == 0 && diagnosticPerType != null)
            {
                // PeeringDB responded but returned 0 networks
                AnsiConsole.MarkupLine("[yellow]PeeringDB returned 0 networks for the given filters.[/]");
                if (typeFilter != null)
                    AnsiConsole.MarkupLine($"[dim]  --type {Markup.Escape(typeFilter)} → {Markup.Escape(string.Join(", ", infoTypes ?? []))}[/]");
                if (countryDisplay != null)
                    AnsiConsole.MarkupLine($"[dim]  --country {Markup.Escape(countryDisplay)} — try a different country code or remove the filter.[/]");
                await CheckPeeringDbConnectivityAsync(peeringDbHttp);
            }
            else if (diagnosticPreEnrich > 0)
            {
                // Had PeeringDB results but RIPE Stat returned no prefixes for any of them
                AnsiConsole.MarkupLine($"[yellow]{diagnosticPreEnrich} network(s) found in PeeringDB but none had routable IPv4 prefixes in RIPE Stat.[/]");
                AnsiConsole.MarkupLine("[dim]RIPE Stat may be temporarily unavailable or rate-limiting.[/]");
                AnsiConsole.MarkupLine("[dim]Try again in a few minutes.[/]");
            }
            else
            {
                // No diagnostics available — unexpected state, do a live check
                AnsiConsole.MarkupLine("[yellow]No hosting networks found. Running connectivity check...[/]");
                await CheckPeeringDbConnectivityAsync(peeringDbHttp);
            }
        }
        else if (maxPingMs.HasValue)
        {
            AnsiConsole.MarkupLine($"[yellow]All {diagnosticCandidates} candidates exceeded --max-ping {maxPingMs} ms or were unreachable.[/]");
            AnsiConsole.MarkupLine("[dim]Try increasing --max-ping or removing it entirely.[/]");
        }
        else
        {
            AnsiConsole.MarkupLine($"[yellow]No providers passed scoring filters ({diagnosticCandidates} candidates scored).[/]");
            if (typeFilter != null)
                AnsiConsole.MarkupLine($"[dim]  --type {Markup.Escape(typeFilter)} may be filtering too aggressively.[/]");
        }
        await ripeCache.FlushIfDirtyAsync();
        return;
    }

    // --from: annotate results with coverage from the IP list.
    if (coverageMap != null)
    {
        results = [.. results.Select(r => r with {
            CoverageCount = coverageMap.GetValueOrDefault(r.Asn, 0),
            TotalListIps  = totalListIps
        })];
    }

    // Traceroute verification: mark candidates whose ASN appears in the route to traceTo.
    if (!string.IsNullOrWhiteSpace(traceTo))
    {
        AnsiConsole.MarkupLine($"[dim]Tracing route to {Markup.Escape(traceTo)}...[/]");
        try
        {
            var hops     = await new TracerouteService().TraceAsync(traceTo);
            var routeAsns = new HashSet<uint>();
            foreach (var hop in hops)
            {
                if (hop.IpAddress == null) continue;
                if (SubnetSearch.Core.Utilities.IpConverter.TryIpToUint(hop.IpAddress, out uint ipUint))
                {
                    var rec = recoIpIndex.Find(ipUint);
                    if (rec.HasValue) routeAsns.Add(rec.Value.Asn);
                }
            }
            if (routeAsns.Count > 0)
                results = [.. results.Select(r => r with { InRoute = routeAsns.Contains(r.Asn) })];
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[yellow]Traceroute failed: {Markup.Escape(ex.Message)}[/]");
        }
    }

    // Apply --sort: re-order results after scoring.
    // "coverage" only makes sense when --from was used (counts IPs from the list per ASN).
    // "latency" falls back to "score" when ICMP is blocked and no latency was measured.
    // Without --from, fall back to "score" to avoid undefined tie-breaking.
    bool noLatencyMeasured = results.Count > 0 && results.All(r => !r.LatencyMs.HasValue);
    string effectiveSort = sortBy?.ToLowerInvariant() switch
    {
        "coverage" when coverageMap == null                        => "score",
        "latency"  when noLatencyMeasured                          => "score",
        { } s => s,
        null    => totalListIps > 0 ? "coverage" : "score",
    };
    if (noLatencyMeasured && sortBy?.ToLowerInvariant() == "latency")
        AnsiConsole.MarkupLine("[yellow]Note: --sort latency has no effect — ICMP blocked, no latency measured. Sorting by score.[/]");

    results = (effectiveSort switch {
        "latency"  => results.OrderBy(r => r.LatencyMs ?? double.MaxValue),
        "rpki"     => results.OrderByDescending(r => r.RpkiScore   ?? 0),
        "size"     => results.OrderByDescending(r => r.TotalIpCount),
        "ip"       => results.OrderByDescending(r => r.TotalIpCount),
        "peering"  => results.OrderByDescending(r => r.PeeringCount ?? 0),
        "upstream" => results.OrderByDescending(r => r.UpstreamCount),
        "coverage" => results.OrderByDescending(r => r.CoverageCount),
        _          => results.OrderByDescending(r => r.Score),
    }).ToList();

    PrintRecommendations(title, results, abuseIpDb != null, greyNoise != null, traceTo != null);

    await ripeCache.FlushIfDirtyAsync();
}

static void PrintRecommendations(
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
            AnsiConsole.MarkupLine("[dim]  subnetSearch --set-key abuseipdb=YOUR_KEY  (free at abuseipdb.com)[/]");
        if (!hasGreyNoise)
            AnsiConsole.MarkupLine("[dim]  subnetSearch --set-key greynoise=YOUR_KEY  (free at greynoise.io)[/]");
        Console.WriteLine();
    }
}

static void PrintTable(List<(string ip, ClassificationResult res)> results)
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
            res.Website != null ? $"[link={res.Website}]{Markup.Escape(res.Website)}[/]" : "N/A"
        );
    }

    AnsiConsole.Write(table);
}

// ================== HELPERS ==================
// Extracts hosting ASNs from local datacenter databases (ipcat, cloud-provider, server-ip-addresses).
// Used to supplement PeeringDB discovery for providers not in PeeringDB's top-N by IX count.
static async Task<IReadOnlyList<(uint Asn, int Count)>> GetLocalHostingAsnsAsync(string dataDir)
{
    var hostingIndex = new HostingRangeIndex();
    await hostingIndex.LoadAsync(dataDir);
    if (hostingIndex.Count == 0) return [];

    var records = await new Ip2AsnLoader().LoadAsync(Path.Combine(dataDir, "ip2asn-v4.tsv.gz"));
    var ipIndex  = new IpRangeIndex(records);

    var asnCounts = new Dictionary<uint, int>();
    foreach (var range in hostingIndex.Ranges)
    {
        var rec = ipIndex.Find(range.StartIp);
        if (rec.HasValue && rec.Value.Asn > 0)
            asnCounts[rec.Value.Asn] = asnCounts.GetValueOrDefault(rec.Value.Asn) + 1;
    }
    return [.. asnCounts.OrderByDescending(kv => kv.Value).Select(kv => (kv.Key, kv.Value))];
}

static bool TryParseCidr(string cidr, out uint start, out uint end) =>
    SubnetSearch.Core.Utilities.IpConverter.TryParseCidr(cidr, out start, out end);

static string UintToIp(uint ip) =>
    SubnetSearch.Core.Utilities.IpConverter.UintToIp(ip);

static async Task CheckPeeringDbConnectivityAsync(HttpClient http)
{
    try
    {
        using var cts  = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var resp = await http.GetAsync(
            "https://www.peeringdb.com/api/net?limit=1&status=ok", cts.Token);
        int code = (int)resp.StatusCode;
        if (resp.IsSuccessStatusCode)
            AnsiConsole.MarkupLine($"[dim]PeeringDB connectivity: [green]OK[/] (HTTP {code})[/]");
        else if (code == 429)
        {
            AnsiConsole.MarkupLine($"[yellow]PeeringDB: HTTP 429 — rate limit active.[/]");
            AnsiConsole.MarkupLine("  subnetSearch --set-key peeringdb=YOUR_KEY  [dim](register free at peeringdb.com)[/]");
        }
        else
            AnsiConsole.MarkupLine($"[yellow]PeeringDB returned HTTP {code}.[/]");
    }
    catch (OperationCanceledException)
    {
        AnsiConsole.MarkupLine("[red]PeeringDB: connection timed out (>10s).[/]");
        AnsiConsole.MarkupLine("[dim]Check your internet connection or configure a proxy: subnetSearch -r --proxy http://...[/]");
    }
    catch (Exception ex)
    {
        AnsiConsole.MarkupLine($"[red]PeeringDB unreachable: {Markup.Escape(ex.Message)}[/]");
        AnsiConsole.MarkupLine("[dim]Check your internet connection or configure a proxy: subnetSearch -r --proxy http://...[/]");
    }
}

static string? GetArgValue(string[] args, string flag)
{
    var idx = Array.IndexOf(args, flag);
    return idx >= 0 && idx + 1 < args.Length ? args[idx + 1] : null;
}

static void PrintVersion()
{
    var asm     = System.Reflection.Assembly.GetExecutingAssembly();
    var infoVer = System.Reflection.CustomAttributeExtensions
                     .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(asm)
                     ?.InformationalVersion;
    // Trim build metadata appended by MSBuild (e.g. "1.2.0-alpha.0+abc1234" → "1.2.0-alpha.0").
    if (infoVer != null)
    {
        int plus = infoVer.IndexOf('+');
        if (plus >= 0) infoVer = infoVer[..plus];
    }
    string ver = infoVer ?? asm.GetName().Version?.ToString(3) ?? "unknown";
    AnsiConsole.MarkupLine($"[bold]SubnetSearch[/] v{ver}");
}

// Validates mode and flags BEFORE data downloads. Returns (true, null) if valid.
static (bool Valid, string? Error) ValidateArgs(string[] args)
{
    if (args.Length == 0) return (true, null);

    // Find the primary mode flag anywhere in args (allows flags before the mode).
    string[] knownModes = ["-a", "-d", "-c", "-l", "-o", "-r"];
    string mode = args.Select(a => a.ToLower())
                      .FirstOrDefault(a => knownModes.Contains(a))
                  ?? args[0].ToLower();

    // Modes that require a positional argument
    if (mode is "-a" or "-d" or "-c" or "-l" or "-o")
    {
        var modeIdx = Array.FindIndex(args, a => a.ToLower() == mode);
        string arg  = modeIdx + 1 < args.Length ? args[modeIdx + 1] : string.Empty;
        if (string.IsNullOrWhiteSpace(arg) || arg.StartsWith('-'))
        {
            string name = mode switch {
                "-a" => "IP address",
                "-d" => "domain",
                "-c" => "CIDR range",
                "-l" => "file path",
                "-o" => "ASN or provider name",
                _    => "argument"
            };
            return (false, $"{mode} requires a {name}.");
        }
    }

    if (mode == "-r")
    {
        string? typeFilter = GetArgValue(args, "--type");
        if (typeFilter != null && ProviderFinder.ResolveInfoTypes(typeFilter) == null)
            return (false,
                $"Unknown --type value: '{typeFilter}'.\n" +
                $"Valid values:\n  {ProviderFinder.ValidTypeValues}");

        string? maxPingStr = GetArgValue(args, "--max-ping");
        if (maxPingStr != null && (!int.TryParse(maxPingStr, out int mp) || mp < 1))
            return (false, $"--max-ping must be a positive integer, got: '{maxPingStr}'");

        string? topStr = GetArgValue(args, "--top");
        if (topStr != null && (!int.TryParse(topStr, out int top) || top < 1))
            return (false, $"--top must be a positive integer, got: '{topStr}'");

        string? sortBy = GetArgValue(args, "--sort");
        string[] validSorts = ["score", "coverage", "latency", "rpki", "size", "peering", "upstream"];
        if (sortBy != null && !validSorts.Contains(sortBy.ToLowerInvariant()))
            return (false,
                $"Unknown --sort value: '{sortBy}'.\n" +
                $"Valid values: {string.Join(", ", validSorts)}");

        string? fromSource = GetArgValue(args, "--from");
        if (fromSource != null
            && !fromSource.StartsWith("http://",  StringComparison.OrdinalIgnoreCase)
            && !fromSource.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            && !File.Exists(fromSource))
            return (false, $"--from: file not found: '{fromSource}'");

        string? countryArg = GetArgValue(args, "--country");
        if (countryArg != null)
        {
            var codes = countryArg.Split(',',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var code in codes)
            {
                if (code.Length != 2 || !code.All(char.IsLetter))
                    return (false,
                        $"--country: '{code}' is not a valid ISO 3166-1 alpha-2 code " +
                        $"(2 letters, e.g. US, DE, GB).");
            }
        }

        string? preset = GetArgValue(args, "--preset");
        string[] validPresets = ["balanced", "performance", "security"];
        if (preset != null && !validPresets.Contains(preset.ToLowerInvariant()))
            return (false,
                $"Unknown --preset value: '{preset}'.\n" +
                $"Valid values: {string.Join(", ", validPresets)}");
    }

    // Catch-all for unknown modes (not a flag either)
    if (!knownModes.Contains(mode))
        return (false, $"Unknown mode: '{args[0]}'");

    return (true, null);
}
