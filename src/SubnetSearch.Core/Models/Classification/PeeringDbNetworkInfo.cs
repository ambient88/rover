namespace SubnetSearch.Core.Models.Classification;

public record PeeringDbNetworkInfo(
    string? Website,
    string? InfoType,
    int?    IxCount = null,   // количество точек обмена трафиком (пирингов)
    int?    NetId   = null    // внутренний ID в PeeringDB для дополнительных запросов
);
