namespace SubnetSearch.Core.Interfaces.Data;

/// <summary>
/// Checks the integrity of a local file.
/// </summary>
public interface IFileIntegrityChecker
{
    string CacheVersion => "1";
    bool IsValid(string filePath);
}
