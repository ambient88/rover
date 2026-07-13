namespace SubnetSearch.Classification;

public class BadAsnLoader
{
    public async Task<HashSet<uint>> LoadAsync(string filePath)
    {
        var asns = new HashSet<uint>();
        if (!File.Exists(filePath))
            return asns;

        string content = await File.ReadAllTextAsync(filePath);
        foreach (var token in content.Split(
                     [' ', '\t', '\r', '\n', ','],
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var trimmed = token;
            if (trimmed.StartsWith('#')) continue;
            if (trimmed.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
                trimmed = trimmed[2..];
            if (uint.TryParse(trimmed, out var asn))
                asns.Add(asn);
        }
        return asns;
    }
}
