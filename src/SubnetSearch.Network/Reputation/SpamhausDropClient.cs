namespace SubnetSearch.Network.Reputation;

public class SpamhausDropClient(HttpClient http)
{
    private volatile HashSet<uint>?  _listedAsns;
    private DateTimeOffset  _loadedAt = DateTimeOffset.MinValue;
    private static readonly TimeSpan Ttl = TimeSpan.FromHours(24);
    private readonly SemaphoreSlim _lock = new(1, 1);

    public async Task LoadAsync(CancellationToken ct = default)
    {
        if (_listedAsns != null && DateTimeOffset.UtcNow - _loadedAt < Ttl)
            return;

        await _lock.WaitAsync(ct);
        try
        {
            // Double-check after acquiring lock.
            if (_listedAsns != null && DateTimeOffset.UtcNow - _loadedAt < Ttl)
                return;

            var text = await http.GetStringAsync(
                "https://www.spamhaus.org/drop/asndrop.txt", ct);
            var asns = new HashSet<uint>();
            foreach (var line in text.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith(';') || string.IsNullOrWhiteSpace(trimmed)) continue;
                var parts  = trimmed.Split(';');
                var asnStr = parts[0].Trim();
                if (asnStr.StartsWith("AS", StringComparison.OrdinalIgnoreCase)
                    && uint.TryParse(asnStr[2..], out var asn))
                    asns.Add(asn);
            }
            _listedAsns = asns;
            _loadedAt   = DateTimeOffset.UtcNow;
        }
        catch
        {
            // On failure keep existing data if available; otherwise use empty set.
            _listedAsns ??= [];
        }
        finally { _lock.Release(); }
    }

    public bool IsListed(uint asn) => _listedAsns?.Contains(asn) ?? false;
}
