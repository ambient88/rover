using SubnetSearch.Cli.Config;

namespace SubnetSearch.Cli;

public sealed record CliContext(
    string     DataDir,
    HttpClient PeeringDbHttp,
    AppConfig  Config,
    bool       ForceWhois);
