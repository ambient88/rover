using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IIpRangeIndex
{
    Ip2AsnRecord? Find(uint ipInt);
}
