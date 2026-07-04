namespace SubnetSearch.Cli.Commands;

public interface ICommand
{
    Task<int> ExecuteAsync(CancellationToken ct);
}
