using SubnetSearch.Core.Interfaces.Data;

namespace SubnetSearch.Data;

public class GZipIntegrityChecker : IFileIntegrityChecker
{
    public bool IsValid(string filePath)
    {
        try
        {
            // The trailer size check detects truncated single-member archives.
            long total = 0;
            using (var fs = File.OpenRead(filePath))
            using (var gz = new GZipStream(fs, CompressionMode.Decompress))
            {
                var buffer = new byte[8192];
                int read;
                while ((read = gz.Read(buffer, 0, buffer.Length)) > 0)
                    total += read;
            }

            if (total == 0) return false;

            using var raw = File.OpenRead(filePath);
            if (raw.Length < 18) return false;
            raw.Seek(-4, SeekOrigin.End);
            var isizeBytes = new byte[4];
            if (raw.Read(isizeBytes, 0, 4) != 4) return false;
            uint isize = (uint)(isizeBytes[0] | (isizeBytes[1] << 8) | (isizeBytes[2] << 16) | (isizeBytes[3] << 24));

            return (uint)(total & 0xFFFFFFFF) == isize;
        }
        catch
        {
            return false;
        }
    }
}
