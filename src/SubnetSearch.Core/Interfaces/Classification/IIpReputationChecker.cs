namespace SubnetSearch.Core.Interfaces.Classification;

public interface IIpReputationChecker
{
    // Возвращает количество источников, в которых замечен IP.
    // 0 — чистый, null — база не загружена.
    int? Check(uint ipInt);
}
