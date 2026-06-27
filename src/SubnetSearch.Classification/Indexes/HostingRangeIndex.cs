using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;
using System.Collections.Immutable;
using System.Text.Json;

namespace SubnetSearch.Classification;

public class HostingRangeIndex : IHostingIpRangeProvider
{
    // ImmutableList is safe to read from any thread without locks.
    // volatile ensures the reference write in LoadAsync is visible to all readers.
    private volatile ImmutableList<HostingIpRange> _ranges = ImmutableList<HostingIpRange>.Empty;
    private readonly SemaphoreSlim _loadLock = new(1, 1);
    public IReadOnlyList<HostingIpRange> Ranges => _ranges;

    public int Count => _ranges.Count;

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

        _ranges = ranges.OrderBy(r => r.StartIp).ToImmutableList();
    }

    public HostingIpRange? Find(uint ipInt)
    {
        int low = 0, high = _ranges.Count - 1;
        while (low <= high)
        {
            int mid = (low + high) / 2;
            var range = _ranges[mid];
            if (ipInt < range.StartIp)
                high = mid - 1;
            else if (ipInt > range.EndIp)
                low = mid + 1;
            else
                return range;
        }
        return null;
    }
    private static bool TryParseIp(string ip, out uint value) =>
        IpConverter.TryIpToUint(ip.Trim(), out value);

    private static bool TryParseCidr(string cidr, out uint start, out uint end) =>
        IpConverter.TryParseCidr(cidr, out start, out end);
}