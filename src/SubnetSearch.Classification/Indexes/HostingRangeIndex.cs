using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;
using System.Collections.Immutable;
using System.Text.Json;

namespace SubnetSearch.Classification;

public class HostingRangeIndex : IHostingIpRangeProvider
{
    // Immutable snapshot of the sorted ranges plus a prefix-max of EndIp, swapped atomically on
    // (re)load. Bundling both in one volatile reference guarantees Find never observes a ranges
    // array and a prefix-max array from different loads. Reading is lock-free.
    private sealed record Snapshot(ImmutableArray<HostingIpRange> Ranges, uint[] PrefixMaxEnd);

    private volatile Snapshot _snapshot = new(ImmutableArray<HostingIpRange>.Empty, Array.Empty<uint>());
    private readonly SemaphoreSlim _loadLock = new(1, 1);
    public IReadOnlyList<HostingIpRange> Ranges => _snapshot.Ranges;

    public int Count => _snapshot.Ranges.Length;

    public async Task LoadAsync(string dataDir, CancellationToken cancellationToken = default)
    {
        await _loadLock.WaitAsync(cancellationToken);
        try
        {
        await LoadInternalAsync(dataDir, cancellationToken);
        }
        finally { _loadLock.Release(); }
    }

    private async Task LoadInternalAsync(string dataDir, CancellationToken cancellationToken)
    {
        var ranges = new List<HostingIpRange>();

        // 1. ipcat
        string ipcatPath = Path.Combine(dataDir, "ipcat-datacenters.csv");
        if (File.Exists(ipcatPath))
        {
            var lines = await File.ReadAllLinesAsync(ipcatPath, cancellationToken);
            foreach (var line in lines)
            {
                var cols = line.Split(',');
                if (cols.Length < 4) continue;
                if (TryParseIp(cols[0], out uint start) && TryParseIp(cols[1], out uint end))
                {
                    string provider = cols[2].Trim('"');
                    string? website = cols[3].Trim('"');
                    if (!string.IsNullOrWhiteSpace(website) && !website.StartsWith("http"))
                        website = "https://" + website;
                    ranges.Add(new HostingIpRange
                    {
                        StartIp = start,
                        EndIp = end,
                        ProviderName = provider,
                        Website = website
                    });
                }
            }
        }

        // 2. rezmoss/cloud-provider-ip-addresses
        string rezmossPath = Path.Combine(dataDir, "cloud-provider-ip-addresses.json");
        if (File.Exists(rezmossPath))
        {
            var json = await File.ReadAllTextAsync(rezmossPath, cancellationToken);
            using var doc = JsonDocument.Parse(json);
            foreach (var element in doc.RootElement.EnumerateArray())
            {
                if (!element.TryGetProperty("cidr", out var cidrProp) ||
                    !element.TryGetProperty("provider", out var providerProp))
                    continue;

                string cidr = cidrProp.GetString() ?? "";
                string provider = providerProp.GetString() ?? "";
                string? website = null;
                if (element.TryGetProperty("website", out var websiteProp))
                    website = websiteProp.GetString();

                if (TryParseCidr(cidr, out uint start, out uint end))
                {
                    ranges.Add(new HostingIpRange
                    {
                        StartIp = start,
                        EndIp = end,
                        ProviderName = provider,
                        Website = website
                    });
                }
            }
        }

        // 3. jhassine/server-ip-addresses
        string jhassinePath = Path.Combine(dataDir, "server-ip-addresses.csv");
        if (File.Exists(jhassinePath))
        {
            var lines = await File.ReadAllLinesAsync(jhassinePath, cancellationToken);
            for (int i = 1; i < lines.Length; i++)
            {
                var cols = lines[i].Split(',');
                if (cols.Length < 4) continue;
                string cidr = cols[0].Trim('"');
                string vendor = cols[3].Trim('"');
                if (TryParseCidr(cidr, out uint start, out uint end))
                {
                    ranges.Add(new HostingIpRange
                    {
                        StartIp = start,
                        EndIp = end,
                        ProviderName = vendor,
                        Website = null
                    });
                }
            }
        }

        var sorted = ranges.OrderBy(r => r.StartIp).ToImmutableArray();

        // prefixMaxEnd[i] = max EndIp over ranges[0..i]. Lets Find stop walking backwards as soon
        // as no earlier range can still reach the queried IP (F1).
        var prefixMaxEnd = new uint[sorted.Length];
        uint running = 0;
        for (int i = 0; i < sorted.Length; i++)
        {
            if (sorted[i].EndIp > running) running = sorted[i].EndIp;
            prefixMaxEnd[i] = running;
        }

        _snapshot = new Snapshot(sorted, prefixMaxEnd);
    }

    // Stabbing query over ranges that may overlap or nest. A plain start-only binary search is
    // wrong for overlaps: a covering range can sit to the left of where the search lands and be
    // skipped (F1). Instead: find the last range whose StartIp <= ip, then walk left while some
    // earlier range can still reach ip (prefixMaxEnd >= ip), returning the first that covers it.
    // Walking from the highest index first yields the most specific (latest-starting) match.
    public HostingIpRange? Find(uint ipInt)
    {
        var snapshot = _snapshot;
        var ranges = snapshot.Ranges;
        var prefixMaxEnd = snapshot.PrefixMaxEnd;

        // Upper bound: largest index whose StartIp <= ipInt.
        int lo = 0, hi = ranges.Length - 1, startIdx = -1;
        while (lo <= hi)
        {
            int mid = lo + (hi - lo) / 2;
            if (ranges[mid].StartIp <= ipInt) { startIdx = mid; lo = mid + 1; }
            else hi = mid - 1;
        }

        for (int j = startIdx; j >= 0 && prefixMaxEnd[j] >= ipInt; j--)
            if (ranges[j].EndIp >= ipInt)
                return ranges[j];

        return null;
    }
    private static bool TryParseIp(string ip, out uint value) =>
        IpConverter.TryIpToUint(ip.Trim(), out value);

    private static bool TryParseCidr(string cidr, out uint start, out uint end) =>
        IpConverter.TryParseCidr(cidr, out start, out end);
}