using SubnetSearch.Core.Interfaces.Data;

namespace SubnetSearch.Data;

public class ZipIntegrityChecker : IFileIntegrityChecker
{
    public bool IsValid(string filePath)
    {
        try
        {
            using var archive = ZipFile.OpenRead(filePath);
            return archive.Entries.Count > 0;
        }
        catch
        {
            return false;
        }
    }
}