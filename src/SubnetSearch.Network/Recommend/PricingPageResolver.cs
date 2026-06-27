namespace SubnetSearch.Network.Recommend;

public static class PricingPageResolver
{
    // ASN → pricing page (highest precision, checked first)
    private static readonly Dictionary<uint, string> ByAsn = new()
    {
        [24940]  = "https://www.hetzner.com/cloud/",
        [16276]  = "https://www.ovhcloud.com/en/vps/",
        [14061]  = "https://www.digitalocean.com/pricing/",
        [63949]  = "https://www.linode.com/pricing/",       // Akamai/Linode
        [20473]  = "https://www.vultr.com/pricing/",
        [34788]  = "https://contabo.com/en/vps/",
        [197540] = "https://contabo.com/en/vps/",
        [8560]   = "https://www.ionos.com/servers/vps",
        [12876]  = "https://www.scaleway.com/en/pricing/",
        [202053] = "https://upcloud.com/pricing/",
        [16509]  = "https://aws.amazon.com/ec2/pricing/on-demand/",
        [15169]  = "https://cloud.google.com/compute/all-pricing",
        [8075]   = "https://azure.microsoft.com/en-us/pricing/details/virtual-machines/",
        [13335]  = "https://www.cloudflare.com/plans/",
        [60068]  = "https://www.cdn77.com/pricing",
        [136907] = "https://www.huaweicloud.com/en-us/pricing/",
        [45090]  = "https://intl.cloud.tencent.com/pricing",
        [37963]  = "https://www.alibabacloud.com/product/ecs",
        [394899] = "https://www.kamatera.com/express/compute/",
        [9009]   = "https://m247.com/connectivity/",
        [51167]  = "https://www.contabo.com/en/vps/",
        [44901]  = "https://serverius.net/",
        [29802]  = "https://www.hivelocity.net/pricing/",
        [32244]  = "https://liquidweb.com/pricing/",
        [400304] = "https://bandwagonhost.com/vps-hosting.php",
    };

    // Keyword in org name → pricing page (fallback)
    private static readonly (string Keyword, string Url)[] ByKeyword =
    [
        ("Hetzner",        "https://www.hetzner.com/cloud/"),
        ("OVH",            "https://www.ovhcloud.com/en/vps/"),
        ("DigitalOcean",   "https://www.digitalocean.com/pricing/"),
        ("Linode",         "https://www.linode.com/pricing/"),
        ("Vultr",          "https://www.vultr.com/pricing/"),
        ("Contabo",        "https://contabo.com/en/vps/"),
        ("IONOS",          "https://www.ionos.com/servers/vps"),
        ("Scaleway",       "https://www.scaleway.com/en/pricing/"),
        ("UpCloud",        "https://upcloud.com/pricing/"),
        ("Amazon",         "https://aws.amazon.com/ec2/pricing/on-demand/"),
        ("Google",         "https://cloud.google.com/compute/all-pricing"),
        ("Microsoft",      "https://azure.microsoft.com/en-us/pricing/details/virtual-machines/"),
        ("Cloudflare",     "https://www.cloudflare.com/plans/"),
        ("Hostinger",      "https://www.hostinger.com/vps-hosting"),
        ("FastComet",      "https://www.fastcomet.com/vps-hosting"),
        ("Kamatera",       "https://www.kamatera.com/express/compute/"),
        ("Hivelocity",     "https://www.hivelocity.net/pricing/"),
        ("Leaseweb",       "https://www.leaseweb.com/cloud/public-cloud"),
        ("Latitude",       "https://www.latitude.sh/pricing"),
        ("Equinix",        "https://metal.equinix.com/product/pricing/"),
        ("Cherry",         "https://www.cherryservers.com/pricing"),
        ("Fasthosts",      "https://www.fasthosts.co.uk/cloud-hosting"),
        ("Alibaba",        "https://www.alibabacloud.com/product/ecs"),
        ("Tencent",        "https://intl.cloud.tencent.com/pricing"),
        ("Huawei",         "https://www.huaweicloud.com/en-us/pricing/"),
    ];

    public static string? Resolve(uint asn, string? orgName)
    {
        if (ByAsn.TryGetValue(asn, out var byAsn)) return byAsn;
        if (string.IsNullOrWhiteSpace(orgName)) return null;
        foreach (var (keyword, url) in ByKeyword)
            if (orgName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                return url;
        return null;
    }
}
