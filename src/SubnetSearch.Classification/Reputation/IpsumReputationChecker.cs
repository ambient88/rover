using SubnetSearch.Core.Interfaces.Classification;

namespace SubnetSearch.Classification;

public class IpsumReputationChecker : IIpReputationChecker
{
    private readonly IReadOnlyDictionary<uint, int> _scores;

    public IpsumReputationChecker(IReadOnlyDictionary<uint, int> scores)
    {
        _scores = scores;
    }

    public int? Check(uint ipInt) =>
        _scores.TryGetValue(ipInt, out int score) ? score : null;
}
