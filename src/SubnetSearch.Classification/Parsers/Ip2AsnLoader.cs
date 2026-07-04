using System.IO.Compression;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Classification;

public class Ip2AsnLoader
{
    public Task<Ip2AsnRecord[]> LoadAsync(string gzipFilePath)
        => Task.Run(() => LoadSync(gzipFilePath));

    private static Ip2AsnRecord[] LoadSync(string gzipFilePath)
    {
        // GZipStream decompresses synchronously regardless of async wrapper.
        // Reading line-by-line with ReadLineAsync in a tight loop over ~400 K entries
        // creates 400 K Task allocations for no benefit. Offload the entire parse to
        // the thread-pool and use synchronous ReadLine throughout.
        var records = new List<Ip2AsnRecord>(500_000);
        var firstLines = new List<string>(5);

        using var fileStream = File.OpenRead(gzipFilePath);
        using var gzipStream = new GZipStream(fileStream, CompressionMode.Decompress);
        using var reader     = new StreamReader(gzipStream, bufferSize: 65_536);

        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (firstLines.Count < 5) firstLines.Add(line);
            if (line.StartsWith('#')) continue;

            var cols = line.Split('\t');
            if (cols.Length < 5) continue;

            try
            {
                uint startIp = IpConverter.IpToUint(cols[0]);
                uint endIp   = IpConverter.IpToUint(cols[1]);

                if (uint.TryParse(cols[2], out uint asn))
                    records.Add(new Ip2AsnRecord
                    {
                        StartIp     = startIp,
                        EndIp       = endIp,
                        Asn         = asn,
                        Country     = cols[3],
                        Description = cols[4],
                    });
            }
            catch { }
        }

        if (records.Count == 0)
            throw new InvalidDataException(
                $"File read but contains no IP2ASN records. " +
                $"Sample lines:\n{string.Join("\n", firstLines)}");

        return records.ToArray();
    }
}