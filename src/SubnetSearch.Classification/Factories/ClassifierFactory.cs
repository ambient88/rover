using SubnetSearch.Classification;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Interfaces.Whois;
using SubnetSearch.Data;

namespace SubnetSearch.Classification;

public static class ClassifierFactory
{
    public static async Task<IIpClassifier> CreateAsync(
        string dataDir,
        bool forceWhois = false,
        HttpClient? peeringDbHttpClient = null)
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
        var peeringDbResolver = new PeeringDbWebsiteResolver(peeringDbHttp);
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
            reputationChecker);
    }

    public static async Task<IDomainClassifier> CreateDomainClassifierAsync(
        string dataDir,
        HttpClient? peeringDbHttpClient = null)
    {
        var ipClassifier  = await CreateAsync(dataDir, peeringDbHttpClient: peeringDbHttpClient);
        IDomainWhoisResolver domainWhois = new DomainWhoisResolver();
        IDnsResolver dnsResolver         = new DnsResolver();
        return new DomainClassifier(ipClassifier, domainWhois, dnsResolver);
    }

    public static async Task<IBatchClassifier> CreateBatchClassifierAsync(
        string dataDir,
        bool forceWhois = false,
        HttpClient? peeringDbHttpClient = null)
    {
        var ipClassifier  = await CreateAsync(dataDir, forceWhois, peeringDbHttpClient);
        IDomainWhoisResolver domainWhois = new DomainWhoisResolver();
        IDnsResolver dnsResolver         = new DnsResolver();
        var domainClassifier             = new DomainClassifier(ipClassifier, domainWhois, dnsResolver);
        return new BatchClassifier(ipClassifier, domainClassifier, new InMemoryCache());
    }

    public static HttpClient CreatePeeringDbHttpClient(HttpClient? bypassClient = null, string? apiKey = null)
    {
        var client = bypassClient ?? new HttpClient();
        client.DefaultRequestHeaders.UserAgent.ParseAdd("SubnetSearch/1.0");
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            // Strip CR/LF to prevent HTTP header injection via malicious key values.
            var sanitizedKey = apiKey.Replace("\r", "").Replace("\n", "").Trim();
            client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", $"Api-Key {sanitizedKey}");
        }
        return client;
    }
}
