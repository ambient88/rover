using SubnetSearch.Classification;
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
        var classifyTask     = domainClassifier.ClassifyDomainAsync(domain, ct);
        var httpTask         = new HttpFingerprintService().FingerprintAsync(domain, ct);
        await Task.WhenAll(classifyTask, httpTask);
        DomainRenderer.PrintDomainResult(classifyTask.Result with { Http = httpTask.Result });
        return 0;
    }
}
