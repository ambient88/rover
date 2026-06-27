namespace SubnetSearch.Core.Models.Classification;

public readonly struct Ip2AsnRecord
{
    public uint StartIp { get; init; }
    public uint EndIp { get; init; }
    public uint Asn { get; init; }
    public string Country { get; init; }
    public string Description { get; init; }
}