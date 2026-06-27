using SubnetSearch.Core.Interfaces.Data;

namespace SubnetSearch.Data;

public class GZipIntegrityChecker : IFileIntegrityChecker
{
    public bool IsValid(string filePath)
    {
        try
        {
            using var fs = File.OpenRead(filePath);
            using var gz = new GZipStream(fs, CompressionMode.Decompress);
            return gz.ReadByte() != -1;
        }
        catch
        {
            return false;
        }
    }
}