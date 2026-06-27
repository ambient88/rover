using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

// Намеренно содержит только поиск — загрузка данных не является ответственностью потребителей индекса.
public interface IHostingIpRangeProvider
{
    HostingIpRange? Find(uint ipInt);
}