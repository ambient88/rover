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
        var diagnosticClock = System.Diagnostics.Stopwatch.StartNew();
        var diagnosticLimit = TimeSpan.FromSeconds(8);
        using var diagnosticBudget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        diagnosticBudget.CancelAfter(diagnosticLimit);
        var diagnosticToken = diagnosticBudget.Token;

        // Classification and network tests run in parallel.
        var classifyTask   = classifier.ClassifyAsync(ip, diagnosticToken);
        var pingTask       = new PingService().PingAsync(ip, cancellationToken: diagnosticToken);
        var tracerouteTask = new TracerouteService().TraceAsync(ip, diagnosticToken);
        var portsTask      = new PortScanner().ScanAsync(ip, cancellationToken: diagnosticToken);
        var httpTask       = new HttpFingerprintService().FingerprintAsync(ip, diagnosticToken);

        try
        {
            await Task.WhenAll(classifyTask, pingTask, tracerouteTask, portsTask, httpTask);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
        }

        SubnetSearch.Core.Models.Classification.TracerouteAnalysis? traceAnalysis = null;
        if (tracerouteTask.IsCompletedSuccessfully)
        {
            var remaining = diagnosticLimit - diagnosticClock.Elapsed;
            if (remaining > TimeSpan.Zero)
            {
                using var analysisBudget = CancellationTokenSource.CreateLinkedTokenSource(ct);
                analysisBudget.CancelAfter(remaining < TimeSpan.FromSeconds(1)
                    ? remaining
                    : TimeSpan.FromSeconds(1));
                try
                {
                    traceAnalysis = await SubnetSearch.Network.TracerouteAnalyzer.AnalyzeAsync(
                        tracerouteTask.Result,
                        new SubnetSearch.Classification.DnsResolver(),
                        analysisBudget.Token);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (OperationCanceledException)
                {
                }
            }
        }

        var classification = classifyTask.IsCompletedSuccessfully
            ? classifyTask.Result
            : new SubnetSearch.Core.Models.Classification.ClassificationResult(
                false, null, null, null, null, "Interactive deadline");
        ClassificationRenderer.PrintResult(
            ip,
            classification,
            pingTask.IsCompletedSuccessfully ? pingTask.Result : null,
            traceAnalysis,
            portsTask.IsCompletedSuccessfully ? portsTask.Result : null,
            httpTask.IsCompletedSuccessfully ? httpTask.Result : null);
        return 0;
    }
}
