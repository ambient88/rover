using SubnetSearch.Classification;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Interfaces.Whois;
using SubnetSearch.Data;

namespace SubnetSearch.Classification;

// Composition root: wires the classifier object graph from data files + HTTP clients. Exercised
// end-to-end by the CLI E2E tests, not unit tests — excluded so it doesn't skew the unit metric.
[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
public static class ClassifierFactory
{
    public static async Task<IIpClassifier> CreateAsync(
        string dataDir,
        bool forceWhois = false,
        HttpClient? peeringDbHttpClient = null,
        string? peeringDbKey = null)
    {
        // Load all four data sources in parallel.
        var hostingRangeIndex = new HostingRangeIndex();

        var loadHostingRanges = hostingRangeIndex.LoadAsync(dataDir);
        var loadIp2Asn        = new Ip2AsnLoader().LoadAsync(Path.Combine(dataDir, "ip2asn-v4.tsv.gz"));
        var loadAsnMeta       = new AsnMetadataParser().LoadAllAsync(Path.Combine(dataDir, "as.json"));
        var loadBadAsns       = new BadAsnLoader().LoadAsync(Path.Combine(dataDir, "bad-asn-list.txt"));
        var loadIpsum         = new IpsumLoader().LoadAsync(Path.Combine(dataDir, "ipsum.txt"));

        await Task.WhenAll(loadHostingRanges, loadIp2Asn, loadAsnMeta, loadBadAsns, loadIpsum);

        var records                           = loadIp2Asn.Result;
        var (hostingAsns, byAsn, byOrg)       = loadAsnMeta.Result;
        var badAsns                           = loadBadAsns.Result;
        var ipIndex                           = new IpRangeIndex(records);

        var peeringDbHttp = peeringDbHttpClient ?? CreatePeeringDbHttpClient();
        var peeringDbResolver = new PeeringDbWebsiteResolver(peeringDbHttp, peeringDbKey);
        var websiteResolver   = new HostingWebsiteResolver(byAsn, byOrg, peeringDbResolver);

        // Enrich hostingAsns with ASNs derived from hosting IP ranges.
        foreach (var range in hostingRangeIndex.Ranges)
        {
            var rec = ipIndex.Find(range.StartIp);
            if (rec.HasValue && rec.Value.Asn > 0)
                hostingAsns.Add(rec.Value.Asn);
        }

        IWhoisResolver whoisResolver = new WhoisResolver();
        IDnsResolver dnsResolver = new DnsResolver();
        IHostingTypeResolver hostingTypeResolver = new HostingTypeResolver(dnsResolver, websiteResolver);

        string dbIpPath = Path.Combine(dataDir, "dbip-city.mmdb.gz");
        // IpApiGeolocator uses a shared static HttpClient; no external client needed.
        var ipApiFallback = new IpApiGeolocator();
        IGeolocator geolocator = File.Exists(dbIpPath)
            ? new CompositeGeolocator(new DbIpGeolocator(dbIpPath), ipApiFallback)
            : ipApiFallback;

        IIpReputationChecker? reputationChecker = loadIpsum.Result.Count > 0
            ? new IpsumReputationChecker(loadIpsum.Result)
            : null;

        return new HostingClassifier(
            hostingRangeIndex,
            ipIndex,
            hostingAsns,
            badAsns,
            websiteResolver,
            whoisResolver,
            forceWhois,
            hostingTypeResolver,
            dnsResolver,
            geolocator,
            reputationChecker,
            peeringDbHttpClient == null ? peeringDbHttp : null);
    }

    public static async Task<IDomainClassifier> CreateDomainClassifierAsync(
        string dataDir,
        HttpClient? peeringDbHttpClient = null,
        string? peeringDbKey = null)
    {
        var ipClassifier  = await CreateAsync(dataDir, peeringDbHttpClient: peeringDbHttpClient, peeringDbKey: peeringDbKey);
        IDomainWhoisResolver domainWhois = new DomainWhoisResolver();
        IDnsResolver dnsResolver         = new DnsResolver();
        return new DomainClassifier(ipClassifier, domainWhois, dnsResolver, ownsIpClassifier: true);
    }

    public static async Task<IBatchClassifier> CreateBatchClassifierAsync(
        string dataDir,
        bool forceWhois = false,
        HttpClient? peeringDbHttpClient = null,
        string? peeringDbKey = null)
    {
        var ipClassifier  = await CreateAsync(dataDir, forceWhois, peeringDbHttpClient, peeringDbKey);
        IDomainWhoisResolver domainWhois = new DomainWhoisResolver();
        IDnsResolver dnsResolver         = new DnsResolver();
        var domainClassifier             = new DomainClassifier(ipClassifier, domainWhois, dnsResolver);
        return new BatchClassifier(ipClassifier, domainClassifier, new InMemoryCache());
    }

    // Authentication is attached to individual PeeringDB requests.
    public static HttpClient CreatePeeringDbHttpClient(HttpClient? bypassClient = null)
    {
        var client = bypassClient ?? new HttpClient();
        client.DefaultRequestHeaders.UserAgent.ParseAdd("rover/1.0");
        return client;
    }
}
