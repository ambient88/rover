using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;
using System.Collections.Immutable;
using System.Text.Json;

namespace SubnetSearch.Classification;

public class HostingRangeIndex : IHostingIpRangeProvider
{
    private const int CacheMagic = 0x48524958;
    private const int CacheVersion = 1;
    private readonly record struct Segment(uint StartIp, uint EndIp, int RangeIndex);
    private readonly record struct Boundary(ulong Position, int RangeIndex, bool IsStart);
    private readonly record struct SourceStamp(bool Exists, long Length, long ModifiedTicks);
    private sealed record Snapshot(
        ImmutableArray<HostingIpRange> Ranges,
        ImmutableArray<Segment> Segments);

    private volatile Snapshot _snapshot = new(
        ImmutableArray<HostingIpRange>.Empty,
        ImmutableArray<Segment>.Empty);
    private readonly SemaphoreSlim _loadLock = new(1, 1);
    private readonly string? _cacheDirectory;

    public HostingRangeIndex(string? cacheDirectory = null)
    {
        _cacheDirectory = cacheDirectory;
    }

    public IReadOnlyList<HostingIpRange> Ranges => _snapshot.Ranges;

    public int Count => _snapshot.Ranges.Length;

    public async Task LoadAsync(string dataDir, CancellationToken cancellationToken = default)
    {
        await _loadLock.WaitAsync(cancellationToken);
        try
        {
            await LoadInternalAsync(dataDir, buildLookupIndex: true, cancellationToken);
        }
        finally { _loadLock.Release(); }
    }

    public async Task LoadRangesAsync(string dataDir, CancellationToken cancellationToken = default)
    {
        await _loadLock.WaitAsync(cancellationToken);
        try
        {
            await LoadInternalAsync(dataDir, buildLookupIndex: false, cancellationToken);
        }
        finally { _loadLock.Release(); }
    }

    private async Task LoadInternalAsync(
        string dataDir,
        bool buildLookupIndex,
        CancellationToken cancellationToken)
    {
        string cacheDirectory = _cacheDirectory ??
            DerivedCachePath.ForDataDirectory(dataDir, "classification");
        string rangesCachePath = Path.Combine(cacheDirectory, "hosting-ranges-v1.bin");
        string indexCachePath = Path.Combine(cacheDirectory, "hosting-index-v1.bin");
        var stamps = GetSourceStamps(dataDir);

        if (buildLookupIndex &&
            TryReadCache(indexCachePath, stamps, requireSegments: true, out var indexedSnapshot))
        {
            _snapshot = indexedSnapshot;
            return;
        }

        if (!buildLookupIndex)
        {
            if (TryReadCache(rangesCachePath, stamps, requireSegments: false, out var rangesSnapshot))
            {
                _snapshot = new Snapshot(rangesSnapshot.Ranges, ImmutableArray<Segment>.Empty);
                return;
            }
        }

        ImmutableArray<HostingIpRange> rawRanges;
        if (TryReadCache(rangesCachePath, stamps, requireSegments: false, out var cachedRanges))
        {
            rawRanges = cachedRanges.Ranges;
        }
        else
        {
            rawRanges = (await LoadRawRangesAsync(dataDir, cancellationToken)).ToImmutableArray();
            TryWriteCache(
                rangesCachePath,
                stamps,
                new Snapshot(rawRanges, ImmutableArray<Segment>.Empty));
        }

        if (!buildLookupIndex)
        {
            _snapshot = new Snapshot(rawRanges, ImmutableArray<Segment>.Empty);
            return;
        }

        var sortedRanges = rawRanges.OrderBy(r => r.StartIp).ToImmutableArray();
        var snapshot = new Snapshot(sortedRanges, BuildSegments(sortedRanges));
        _snapshot = snapshot;
        TryWriteCache(indexCachePath, stamps, snapshot);
    }

    private static async Task<List<HostingIpRange>> LoadRawRangesAsync(
        string dataDir,
        CancellationToken cancellationToken)
    {
        var ranges = new List<HostingIpRange>();

        // 1. ipcat
        string ipcatPath = Path.Combine(dataDir, "ipcat-datacenters.csv");
        if (File.Exists(ipcatPath))
        {
            var lines = await File.ReadAllLinesAsync(ipcatPath, cancellationToken);
            foreach (var line in lines)
            {
                var cols = CsvLine.Parse(line);
                if (cols.Count < 4) continue;
                if (TryParseIp(cols[0], out uint start) && TryParseIp(cols[1], out uint end))
                {
                    string provider = cols[2];
                    string? website = cols[3];
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
            await using var stream = File.OpenRead(rezmossPath);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
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
                var cols = CsvLine.Parse(lines[i]);
                if (cols.Count < 4) continue;
                string cidr = cols[0];
                string vendor = cols[3];
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

        return ranges;
    }

    private static SourceStamp[] GetSourceStamps(string dataDir) =>
    [
        GetSourceStamp(Path.Combine(dataDir, "ipcat-datacenters.csv")),
        GetSourceStamp(Path.Combine(dataDir, "cloud-provider-ip-addresses.json")),
        GetSourceStamp(Path.Combine(dataDir, "server-ip-addresses.csv"))
    ];

    private static SourceStamp GetSourceStamp(string path)
    {
        var file = new FileInfo(path);
        return file.Exists
            ? new SourceStamp(true, file.Length, file.LastWriteTimeUtc.Ticks)
            : new SourceStamp(false, 0, 0);
    }

    private static bool TryReadCache(
        string cachePath,
        SourceStamp[] expectedStamps,
        bool requireSegments,
        out Snapshot snapshot)
    {
        snapshot = new Snapshot(
            ImmutableArray<HostingIpRange>.Empty,
            ImmutableArray<Segment>.Empty);
        try
        {
            if (!File.Exists(cachePath)) return false;
            using var reader = new BinaryReader(File.OpenRead(cachePath));
            if (reader.ReadInt32() != CacheMagic || reader.ReadInt32() != CacheVersion)
                return false;

            int stampCount = reader.ReadInt32();
            if (stampCount != expectedStamps.Length) return false;
            for (int i = 0; i < stampCount; i++)
            {
                var actual = new SourceStamp(
                    reader.ReadBoolean(),
                    reader.ReadInt64(),
                    reader.ReadInt64());
                if (actual != expectedStamps[i]) return false;
            }

            int rangeCount = reader.ReadInt32();
            if (rangeCount < 0 || rangeCount > 5_000_000) return false;
            var ranges = ImmutableArray.CreateBuilder<HostingIpRange>(rangeCount);
            for (int i = 0; i < rangeCount; i++)
            {
                ranges.Add(new HostingIpRange
                {
                    StartIp = reader.ReadUInt32(),
                    EndIp = reader.ReadUInt32(),
                    ProviderName = reader.ReadString(),
                    Website = reader.ReadBoolean() ? reader.ReadString() : null
                });
            }

            int segmentCount = reader.ReadInt32();
            if (segmentCount < 0 || segmentCount > 10_000_000 ||
                (requireSegments && rangeCount > 0 && segmentCount == 0))
                return false;
            var segments = ImmutableArray.CreateBuilder<Segment>(segmentCount);
            for (int i = 0; i < segmentCount; i++)
            {
                uint startIp = reader.ReadUInt32();
                uint endIp = reader.ReadUInt32();
                int rangeIndex = reader.ReadInt32();
                if ((uint)rangeIndex >= (uint)rangeCount) return false;
                segments.Add(new Segment(startIp, endIp, rangeIndex));
            }

            if (reader.BaseStream.Position != reader.BaseStream.Length) return false;
            snapshot = new Snapshot(ranges.MoveToImmutable(), segments.MoveToImmutable());
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void TryWriteCache(
        string cachePath,
        SourceStamp[] stamps,
        Snapshot snapshot)
    {
        string? tempPath = null;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(cachePath)!);
            tempPath = cachePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            using (var writer = new BinaryWriter(File.Create(tempPath)))
            {
                writer.Write(CacheMagic);
                writer.Write(CacheVersion);
                writer.Write(stamps.Length);
                foreach (var stamp in stamps)
                {
                    writer.Write(stamp.Exists);
                    writer.Write(stamp.Length);
                    writer.Write(stamp.ModifiedTicks);
                }

                writer.Write(snapshot.Ranges.Length);
                foreach (var range in snapshot.Ranges)
                {
                    writer.Write(range.StartIp);
                    writer.Write(range.EndIp);
                    writer.Write(range.ProviderName ?? string.Empty);
                    writer.Write(range.Website != null);
                    if (range.Website != null) writer.Write(range.Website);
                }

                writer.Write(snapshot.Segments.Length);
                foreach (var segment in snapshot.Segments)
                {
                    writer.Write(segment.StartIp);
                    writer.Write(segment.EndIp);
                    writer.Write(segment.RangeIndex);
                }
            }
            File.Move(tempPath, cachePath, true);
            tempPath = null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Cache writes are best effort. A later run can rebuild after an I/O or permission failure.
            // are expected here; anything else (a real bug) is allowed to surface (ARCH-04).
        }
        finally
        {
            if (tempPath != null)
            {
                try { File.Delete(tempPath); } catch { }
            }
        }
    }

    public HostingIpRange? Find(uint ipInt)
    {
        var snapshot = _snapshot;
        var segments = snapshot.Segments;

        int lo = 0, hi = segments.Length - 1;
        while (lo <= hi)
        {
            int mid = lo + (hi - lo) / 2;
            var segment = segments[mid];
            if (ipInt < segment.StartIp) hi = mid - 1;
            else if (ipInt > segment.EndIp) lo = mid + 1;
            else return snapshot.Ranges[segment.RangeIndex];
        }

        return null;
    }

    private static ImmutableArray<Segment> BuildSegments(
        ImmutableArray<HostingIpRange> ranges)
    {
        if (ranges.IsEmpty) return ImmutableArray<Segment>.Empty;

        var boundaries = new Boundary[ranges.Length * 2];
        for (int i = 0; i < ranges.Length; i++)
        {
            boundaries[i * 2] = new Boundary(ranges[i].StartIp, i, true);
            boundaries[i * 2 + 1] = new Boundary((ulong)ranges[i].EndIp + 1, i, false);
        }

        Array.Sort(boundaries, static (left, right) => left.Position.CompareTo(right.Position));
        var active = new SortedSet<int>();
        var segments = ImmutableArray.CreateBuilder<Segment>();
        ulong previous = boundaries[0].Position;
        int boundaryIndex = 0;

        while (boundaryIndex < boundaries.Length)
        {
            ulong position = boundaries[boundaryIndex].Position;
            if (position > previous && active.Count > 0)
                AddSegment(segments, (uint)previous, (uint)(position - 1), active.Max);

            while (boundaryIndex < boundaries.Length &&
                   boundaries[boundaryIndex].Position == position)
            {
                var boundary = boundaries[boundaryIndex++];
                if (boundary.IsStart) active.Add(boundary.RangeIndex);
                else active.Remove(boundary.RangeIndex);
            }

            previous = position;
        }

        return segments.ToImmutable();
    }

    private static void AddSegment(
        ImmutableArray<Segment>.Builder segments,
        uint startIp,
        uint endIp,
        int rangeIndex)
    {
        if (segments.Count > 0)
        {
            var previous = segments[^1];
            if (previous.RangeIndex == rangeIndex && (ulong)previous.EndIp + 1 == startIp)
            {
                segments[^1] = previous with { EndIp = endIp };
                return;
            }
        }

        segments.Add(new Segment(startIp, endIp, rangeIndex));
    }

    private static bool TryParseIp(string ip, out uint value) =>
        IpConverter.TryIpToUint(ip.Trim(), out value);

    private static bool TryParseCidr(string cidr, out uint start, out uint end) =>
        IpConverter.TryParseCidr(cidr, out start, out end);
}
