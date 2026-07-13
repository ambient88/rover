using SubnetSearch.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Network.Http;
using SubnetSearch.Cli.Rendering;

namespace SubnetSearch.Cli.Commands;

public sealed class DomainCommand(CliContext ctx, string domain) : ICommand
{
    public async Task<int> ExecuteAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(domain))
            throw new ArgumentException("Provide a domain name.");
        using var domainClassifier = await ClassifierFactory.CreateDomainClassifierAsync(ctx.DataDir, ctx.PeeringDbHttp, ctx.Config.PeeringDbKey);
        using var commandBudget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        commandBudget.CancelAfter(TimeSpan.FromSeconds(8));
        var classifyTask = domainClassifier.ClassifyDomainAsync(domain, commandBudget.Token);
        var httpTask = new HttpFingerprintService().FingerprintAsync(domain, commandBudget.Token);
        try
        {
            await Task.WhenAll(classifyTask, httpTask);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
        }

        var result = classifyTask.IsCompletedSuccessfully
            ? classifyTask.Result
            : new DomainClassificationResult(
                domain, [], null, null, [], null, null, null, [], null);
        DomainRenderer.PrintDomainResult(result with
        {
            Http = httpTask.IsCompletedSuccessfully ? httpTask.Result : null
        });
        return 0;
    }
}
