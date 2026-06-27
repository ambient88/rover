namespace SubnetSearch.Classification;

public class BadAsnLoader
{
    public async Task<HashSet<uint>> LoadAsync(string filePath)
    {
        var asns = new HashSet<uint>();
        if (!File.Exists(filePath))
            return asns;

        var lines = await File.ReadAllLinesAsync(filePath);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith('#')) continue;
            // Убираем префикс "AS" если есть
            if (trimmed.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
                trimmed = trimmed[2..];
            if (uint.TryParse(trimmed, out var asn))
                asns.Add(asn);
        }
        return asns;
    }
}