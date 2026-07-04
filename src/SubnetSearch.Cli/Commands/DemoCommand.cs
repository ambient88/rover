using SubnetSearch.Classification;
using SubnetSearch.Cli.Rendering;

namespace SubnetSearch.Cli.Commands;

public sealed class DemoCommand(CliContext ctx) : ICommand
{
    public async Task<int> ExecuteAsync(CancellationToken ct)
    {
        using var peeringDbHttp = ClassifierFactory.CreatePeeringDbHttpClient();
        var classifier = await ClassifierFactory.CreateAsync(ctx.DataDir, ctx.ForceWhois, peeringDbHttp);
        const string testIp = "8.8.8.8";
        AnsiConsole.MarkupLine($"[cyan]Demo check IP: {Markup.Escape(testIp)}[/]");
        var result = await classifier.ClassifyAsync(testIp);
        ClassificationRenderer.PrintResult(testIp, result);
        return 0;
    }
}
