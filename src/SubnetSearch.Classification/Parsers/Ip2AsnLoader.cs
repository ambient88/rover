using System.IO.Compression;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Classification;

public class Ip2AsnLoader
{
    public async Task<Ip2AsnRecord[]> LoadAsync(string gzipFilePath)
    {
        var records = new List<Ip2AsnRecord>();
        int totalLines = 0;
        var firstLines = new List<string>();

        await using var fileStream = File.OpenRead(gzipFilePath);
        await using var gzipStream = new GZipStream(fileStream, CompressionMode.Decompress);
        using var reader = new StreamReader(gzipStream);

        while (!reader.EndOfStream)
        {
            var line = await reader.ReadLineAsync();
            if (line == null) break;
            totalLines++;
            if (firstLines.Count < 5) firstLines.Add(line);

            if (line.StartsWith('#')) continue;

            // Разделяем по табуляции (TSV)
            var cols = line.Split('\t');
            if (cols.Length < 5) continue;

            try
            {
                // IP-адреса в dotted‑decimal, конвертируем через IpConverter
                uint startIp = IpConverter.IpToUint(cols[0]);
                uint endIp = IpConverter.IpToUint(cols[1]);

                if (uint.TryParse(cols[2], out uint asn))
                {
                    string country = cols[3];
                    string description = cols[4]; // описание — всё, что в пятом столбце

                    records.Add(new Ip2AsnRecord
                    {
                        StartIp = startIp,
                        EndIp = endIp,
                        Asn = asn,
                        Country = country,
                        Description = description
                    });
                }
            }
            catch
            {
                // Игнорируем строки с ошибками (например, невалидный IP)
            }
        }

        if (records.Count == 0)
        {
            throw new InvalidDataException(
                $"File read but contains no IP2ASN records. " +
                $"Sample lines:\n{string.Join("\n", firstLines)}");
        }

        return records.ToArray();
    }
}