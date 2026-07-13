using System.Net;
using SubnetSearch.Classification;
using SubnetSearch.Network;
using SubnetSearch.Network.Http;
using SubnetSearch.Cli.Rendering;

namespace SubnetSearch.Cli.Commands;

public sealed class SingleIpCommand(CliContext ctx, string ip) : ICommand
{
    public async Task<int> ExecuteAsync(CancellationToken ct)
    {
        if (!IPAddress.TryParse(ip, out var parsedIp))
            throw new ArgumentException($"Invalid IP address: {ip}");
        if (parsedIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ArgumentException($"Only IPv4 addresses are supported: {ip}");

        using var classifier = await ClassifierFactory.CreateAsync(ctx.DataDir, ctx.ForceWhois, ctx.PeeringDbHttp, ctx.Config.PeeringDbKey);

        // Classification and network tests run in parallel.
        var classifyTask   = classifier.ClassifyAsync(ip, ct);
        var pingTask       = new PingService().PingAsync(ip, cancellationToken: ct);
        var tracerouteTask = new TracerouteService().TraceAsync(ip, ct);
        var portsTask      = new PortScanner().ScanAsync(ip, cancellationToken: ct);
        var httpTask       = new HttpFingerprintService().FingerprintAsync(ip, ct);

        await Task.WhenAll(classifyTask, pingTask, tracerouteTask, portsTask, httpTask);

        // Traceroute analysis: PTR resolution + proxy detection runs after hops are available.
        var traceAnalysis = await SubnetSearch.Network.TracerouteAnalyzer.AnalyzeAsync(
            tracerouteTask.Result, new SubnetSearch.Classification.DnsResolver(), ct);

        ClassificationRenderer.PrintResult(ip, classifyTask.Result, pingTask.Result, traceAnalysis, portsTask.Result, httpTask.Result);
        return 0;
    }
}
