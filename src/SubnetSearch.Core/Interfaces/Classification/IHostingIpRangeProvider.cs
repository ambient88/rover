using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

// Intentionally exposes lookups only. Loading data is not the responsibility of index consumers.
public interface IHostingIpRangeProvider
{
    HostingIpRange? Find(uint ipInt);
}