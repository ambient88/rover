using SubnetSearch.Core.Interfaces.Data;

namespace SubnetSearch.Data;

public class GZipIntegrityChecker : IFileIntegrityChecker
{
    public bool IsValid(string filePath)
    {
        try
        {
            // Decompress the whole stream and compare the byte count against the gzip trailer's
            // ISIZE (original size mod 2^32, little-endian in the last 4 bytes). Reading only the
            // first byte waved through a partial download (F8); even a full read is not enough,
            // because .NET's GZipStream returns 0 at a truncation instead of faulting. The ISIZE
            // cross-check catches a lost/corrupt trailer. Assumes a single-member gzip (the data
            // sources here never concatenate members).
            long total = 0;
            using (var fs = File.OpenRead(filePath))
            using (var gz = new GZipStream(fs, CompressionMode.Decompress))
            {
                var buffer = new byte[8192];
                int read;
                while ((read = gz.Read(buffer, 0, buffer.Length)) > 0)
                    total += read;
            }

            if (total == 0) return false; // empty (or header-only) — treat as invalid, as before

            using var raw = File.OpenRead(filePath);
            if (raw.Length < 18) return false; // 10-byte header + 8-byte trailer minimum
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