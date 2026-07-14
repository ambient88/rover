namespace SubnetSearch.Core.Interfaces.Classification;

public interface IIpReputationChecker
{
    // Returns the number of sources that flagged the IP.
    // 0 = clean, null = database not loaded.
    int? Check(uint ipInt);
}
