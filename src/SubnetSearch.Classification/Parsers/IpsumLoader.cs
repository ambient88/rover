namespace SubnetSearch.Classification;

public class IpsumLoader
{
    public async Task<Dictionary<uint, int>> LoadAsync(string filePath)
    {
        var scores = new Dictionary<uint, int>();
        if (!File.Exists(filePath))
            return scores;

        var lines = await File.ReadAllLinesAsync(filePath);
        foreach (var line in lines)
        {
            if (line.Length == 0 || line[0] == '#') continue;

            var tab = line.IndexOf('\t');
            if (tab < 0) continue;

            string ipPart    = line[..tab];
            string scorePart = line[(tab + 1)..];

            if (System.Net.IPAddress.TryParse(ipPart, out var addr)
                && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                && int.TryParse(scorePart, out int score))
            {
                var bytes = addr.GetAddressBytes();
                uint ipInt = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
                scores[ipInt] = score;
            }
        }
        return scores;
    }
}
