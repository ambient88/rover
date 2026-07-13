using MaxMind.Db;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using System.IO.Compression;
using System.Net;

namespace SubnetSearch.Classification;

// Thin wrapper over the MaxMind/DB-IP reader (file + native lookups) — integration-tested only.
[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
public sealed class DbIpGeolocator : IGeolocator, IDisposable
{
    private readonly Reader? _reader;

    public DbIpGeolocator(string dbPath)
    {
        if (!File.Exists(dbPath)) return;
        try
        {
            string mmdbPath = DecompressIfNeeded(dbPath);
            _reader = new Reader(mmdbPath);
        }
        catch
        {
            _reader = null;
        }
    }

    // Decompresses .mmdb.gz next to the source; re-decompresses only when the
    // gz file is newer than the already-extracted .mmdb.
    private static string DecompressIfNeeded(string gzPath)
    {
        string mmdbPath = Path.ChangeExtension(gzPath, null); // strips .gz to get .mmdb
        var gzInfo   = new FileInfo(gzPath);
        var mmdbInfo = new FileInfo(mmdbPath);

        if (!mmdbInfo.Exists || gzInfo.LastWriteTimeUtc > mmdbInfo.LastWriteTimeUtc)
        {
            using var fs  = File.OpenRead(gzPath);
            using var gz  = new GZipStream(fs, CompressionMode.Decompress);
            using var out_ = File.Create(mmdbPath);
            gz.CopyTo(out_);
        }

        return mmdbPath;
    }

    public GeoLocation? Locate(string ipAddress)
    {
        if (_reader == null || !IPAddress.TryParse(ipAddress, out var ip))
            return null;
        try
        {
            var record = _reader.Find<Dictionary<string, object>>(ip);
            if (record == null) return null;

            string? city    = GetString(record, "city", "names", "en");
            string? country = GetString(record, "country", "iso_code");
            string? region  = null;
            if (record.TryGetValue("subdivisions", out var subsObj) && subsObj is List<object> subs && subs.Count > 0)
                region = GetString(subs[0] as Dictionary<string, object>, "names", "en");

            double? lat = null, lon = null;
            string? timezone = null;
            if (record.TryGetValue("location", out var locObj) && locObj is Dictionary<string, object> loc)
            {
                lat      = loc.TryGetValue("latitude",  out var latObj) && latObj is double ld ? ld : null;
                lon      = loc.TryGetValue("longitude", out var lonObj) && lonObj is double lo ? lo : null;
                timezone = loc.TryGetValue("time_zone", out var tzObj)  ? tzObj as string : null;
            }

            if (city == null && region == null && lat == null && country == null) return null;
            return new GeoLocation(city, region, lat, lon, timezone, country);
        }
        catch
        {
            return null;
        }
    }

    private static string? GetString(Dictionary<string, object>? dict, params string[] keys)
    {
        object? cur = dict;
        foreach (var key in keys)
        {
            if (cur is not Dictionary<string, object> d || !d.TryGetValue(key, out cur))
                return null;
        }
        return cur as string;
    }

    public void Dispose() => _reader?.Dispose();
}
