using SubnetSearch.Core.Interfaces.Data;
using SubnetSearch.Core.Models.Data;

namespace SubnetSearch.Data;

public static class DownloadManagerFactory
{
    // bgp.tools requires a non-default User-Agent identifying the client with a contact
    // ("Default user agents are not supported" — https://bgp.tools/kb/api).
    // The same UA is sent to all download hosts.
    public const string UserAgent =
        "SubnetSearch/1.0 (github.com/ambient88/rover; contact: thriilerchiller123@gmail.com)";

    public static HttpClient CreateHttpClient(DownloadOptions? options = null)
    {
        var handler = new HttpClientHandler
        {
            AutomaticDecompression = System.Net.DecompressionMethods.None
        };
        if (options?.Proxy is not null)
            handler.Proxy = new System.Net.WebProxy(options.Proxy);
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(options?.TimeoutSeconds ?? 600) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        return client;
    }

    public static DownloadManager Create(HttpClient httpClient, string dataDir)
    {
        var downloader = CreateDownloader(httpClient);
        var storage    = CreateStorage(dataDir);
        var files      = GetDefaultFiles();
        var metaStore  = new FileMetadataStore(dataDir);
        return new DownloadManager(downloader, storage, files, metaStore);
    }

    public static IFileDownloader CreateDownloader(HttpClient httpClient)
        => new HttpFileDownloader(httpClient);

    public static IFileStorage CreateStorage(string dataDir)
    {
        var integrityCheckers = new Dictionary<string, IFileIntegrityChecker>
        {
            { ".tsv.gz",  new GZipIntegrityChecker() },
            { ".mmdb.gz", new GZipIntegrityChecker() },
            { ".json",    new JsonIntegrityChecker()  }
        };
        return new LocalFileStorage(dataDir, integrityCheckers);
    }

    public static IReadOnlyList<FileDescriptor> GetDefaultFiles()
    {
        // URL DB-IP генерируется динамически — база обновляется ежемесячно.
        var now = DateTime.UtcNow;
        string dbIpUrl = $"https://download.db-ip.com/free/dbip-city-lite-{now:yyyy-MM}.mmdb.gz";

        // MinSize guards against empty/truncated downloads only — integrity (gzip/json) is primary.
        var files = new List<FileDescriptor>
        {
            new("https://iptoasn.com/data/ip2asn-v4.tsv.gz",                                                                         "ip2asn-v4.tsv.gz",                4_000_000,  TimeSpan.FromDays(7)),
            new("https://raw.githubusercontent.com/ipverse/as-metadata/master/as.json",                                              "as.json",                         500_000,    TimeSpan.FromDays(7)),
            new("https://raw.githubusercontent.com/podlibre/ipcat/master/datacenters.csv",                                           "ipcat-datacenters.csv",           50_000,     TimeSpan.FromDays(14)),
            new("https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/all_providers/all_providers.json",        "cloud-provider-ip-addresses.json", 50_000,    TimeSpan.FromDays(14)),
            new("https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv",                        "server-ip-addresses.csv",         10_000,     TimeSpan.FromDays(14)),
            new(dbIpUrl,                                                                                                              "dbip-city.mmdb.gz",               5_000_000,  TimeSpan.FromDays(30)),
            new("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",                                                 "ipsum.txt",                       100_000,    TimeSpan.FromDays(3)),
            new("https://raw.githubusercontent.com/ambient88/rover/main/data/asn-exclusions.json",                                    "asn-exclusions.json",             500,        TimeSpan.FromDays(14)),
            //new("https://bgp.tools/asns.csv", "bgptools-asns.csv", 100_000, TimeSpan.FromDays(7)),
        };

        // bgp.tools community-теги ASN — локальная замена ASN-типов ipapi.is (AsnTypeResolver).
        // Файлы маленькие (единицы–сотни КБ); event.csv ~22 строки, поэтому MinSize минимальный.
        foreach (var tag in new[] { "vpsh", "cdn", "dsl", "mobile", "satnet", "gov", "uni", "perso", "corp", "biznet", "event" })
            files.Add(new($"https://bgp.tools/tags/{tag}.csv", $"bgptools-{tag}.csv", 100, TimeSpan.FromDays(7)));

        return files;
    }
}