using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Classification;

public class IpRangeIndex : IIpRangeIndex
{
    private readonly Ip2AsnRecord[] _records;

    public IpRangeIndex(Ip2AsnRecord[] records)
    {
        _records = records.OrderBy(r => r.StartIp).ToArray();
    }

    public Ip2AsnRecord? Find(uint ipInt)
    {
        int low = 0, high = _records.Length - 1;

        while (low <= high)
        {
            int mid = (low + high) / 2;
            var rec = _records[mid];

            if (ipInt < rec.StartIp)
                high = mid - 1;
            else if (ipInt > rec.EndIp)
                low = mid + 1;
            else
                return rec;
        }

        return null;
    }
}
