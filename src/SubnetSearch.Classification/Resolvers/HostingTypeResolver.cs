using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using System.Net;

namespace SubnetSearch.Classification;

public class HostingTypeResolver : IHostingTypeResolver
{
    private readonly IDnsResolver _dnsResolver;
    private readonly IWebsiteResolver _websiteResolver;

    public HostingTypeResolver(IDnsResolver dnsResolver, IWebsiteResolver websiteResolver)
    {
        _dnsResolver = dnsResolver ?? throw new ArgumentNullException(nameof(dnsResolver));
        _websiteResolver = websiteResolver ?? throw new ArgumentNullException(nameof(websiteResolver));
    }

    public async Task<HostingType> ResolveAsync(
        string ipAddress,
        uint? asn,
        string? orgName,
        CancellationToken cancellationToken = default)
    {
        // Layer 1: the PTR record, the most specific signal for a given IP.
        string? ptr = null;
        if (IPAddress.TryParse(ipAddress, out var ip))
            ptr = await _dnsResolver.ReverseDnsAsync(ip, cancellationToken);

        return await ResolveWithPtrAsync(ipAddress, asn, orgName, ptr, cancellationToken);
    }

    public async Task<HostingType> ResolveWithPtrAsync(
        string ipAddress,
        uint? asn,
        string? orgName,
        string? ptr,
        CancellationToken cancellationToken = default)
    {
        var fromPtr = ClassificationRules.ResolveHostingTypeFromPtr(ptr);
        if (fromPtr.HasValue)
            return fromPtr.Value;

        // Layer 2: PeeringDB info_type, structured data about the ASN.
        if (asn.HasValue)
        {
            var info = await _websiteResolver.GetNetworkInfoFromPeeringDbAsync(asn.Value, cancellationToken);
            if (info?.InfoType != null)
            {
                var fromPdb = MapInfoType(info.InfoType);
                if (fromPdb != HostingType.Unknown)
                    return fromPdb;
            }
        }

        // Layer 3: keywords in the organization name, as a fallback.
        return ClassificationRules.ResolveHostingType(orgName) ?? HostingType.Unknown;
    }

    private static HostingType MapInfoType(string infoType) => infoType.ToLowerInvariant() switch
    {
        // "Content" means CDN or cloud; the PTR in step 1 should already have told them apart,
        // so here we return Cloud as a general "content hosting" bucket.
        "content"    => HostingType.Cloud,
        "hosting"    => HostingType.Vps,
        "enterprise" => HostingType.Colocation,
        _            => HostingType.Unknown,
    };
}
