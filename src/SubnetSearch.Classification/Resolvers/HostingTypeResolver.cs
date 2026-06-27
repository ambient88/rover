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
        // Слой 1: PTR-запись — наиболее специфичный сигнал для конкретного IP.
        if (IPAddress.TryParse(ipAddress, out var ip))
        {
            var ptr = await _dnsResolver.ReverseDnsAsync(ip, cancellationToken);
            var fromPtr = ClassificationRules.ResolveHostingTypeFromPtr(ptr);
            if (fromPtr.HasValue)
                return fromPtr.Value;
        }

        // Слой 2: PeeringDB info_type — структурированные данные об ASN.
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

        // Слой 3: ключевые слова в названии организации — fallback.
        return ClassificationRules.ResolveHostingType(orgName) ?? HostingType.Unknown;
    }

    private static HostingType MapInfoType(string infoType) => infoType.ToLowerInvariant() switch
    {
        // "Content" — CDN или облако; PTR на шаге 1 должен был уже различить,
        // поэтому здесь возвращаем Cloud как обобщённый «хостинг контента».
        "content"    => HostingType.Cloud,
        "hosting"    => HostingType.Vps,
        "enterprise" => HostingType.Colocation,
        _            => HostingType.Unknown,
    };
}
