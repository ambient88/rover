using SubnetSearch.Core.Interfaces.Data;

namespace SubnetSearch.Data;

public class JsonIntegrityChecker : IFileIntegrityChecker
{
    public bool IsValid(string filePath)
    {
        try
        {
            var text = File.ReadAllText(filePath);
            JsonDocument.Parse(text);
            return true;
        }
        catch
        {
            return false;
        }
    }
}