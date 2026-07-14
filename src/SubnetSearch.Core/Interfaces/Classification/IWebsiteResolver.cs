using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IWebsiteResolver
{
    string? GetWebsite(uint? asn, string? organization, string? whoisWebsite = null);

    Task<PeeringDbNetworkInfo?> GetNetworkInfoFromPeeringDbAsync(uint asn, CancellationToken cancellationToken = default);

    // Returns the names of the IXPs the ASN participates in.
    Task<IReadOnlyList<string>?> GetIxLocationsAsync(uint asn, CancellationToken cancellationToken = default);

    // Default: pulls only the website from the shared cached request.
    async Task<string?> GetWebsiteFromPeeringDbAsync(uint asn, CancellationToken cancellationToken = default)
    {
        var info = await GetNetworkInfoFromPeeringDbAsync(asn, cancellationToken).ConfigureAwait(false);
        return info?.Website;
    }
}
