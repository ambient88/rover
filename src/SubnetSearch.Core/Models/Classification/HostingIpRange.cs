namespace SubnetSearch.Core.Models.Classification;

public readonly struct HostingIpRange
{
    public uint StartIp { get; init; }
    public uint EndIp { get; init; }
    public string ProviderName { get; init; }
    public string? Website { get; init; }
}