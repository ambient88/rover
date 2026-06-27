using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Interfaces.Whois;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;
using System.Net;

namespace SubnetSearch.Classification;

public class HostingClassifier : IIpClassifier, IDisposable
{
    private readonly IHostingIpRangeProvider _hostingRangeProvider;
    private readonly IIpRangeIndex _ipIndex;
    private readonly HashSet<uint> _hostingAsns;
    private readonly HashSet<uint> _badAsns;
    private readonly IWebsiteResolver _websiteResolver;
    private readonly IWhoisResolver? _whoisResolver;
    private readonly IHostingTypeResolver _hostingTypeResolver;
    private readonly IDnsResolver _dnsResolver;
    private readonly IGeolocator? _geolocator;
    private readonly IIpReputationChecker? _reputationChecker;
    private readonly bool _forceWhois;

    public HostingClassifier(
        IHostingIpRangeProvider hostingRangeProvider,
        IIpRangeIndex ipIndex,
        HashSet<uint> hostingAsns,
        HashSet<uint> badAsns,
        IWebsiteResolver websiteResolver,
        IWhoisResolver? whoisResolver,
        bool forceWhois,
        IHostingTypeResolver hostingTypeResolver,
        IDnsResolver dnsResolver,
        IGeolocator? geolocator = null,
        IIpReputationChecker? reputationChecker = null)
    {
        _hostingRangeProvider  = hostingRangeProvider  ?? throw new ArgumentNullException(nameof(hostingRangeProvider));
        _ipIndex               = ipIndex               ?? throw new ArgumentNullException(nameof(ipIndex));
        _hostingAsns           = hostingAsns           ?? throw new ArgumentNullException(nameof(hostingAsns));
        _badAsns               = badAsns               ?? [];
        _websiteResolver       = websiteResolver       ?? throw new ArgumentNullException(nameof(websiteResolver));
        _whoisResolver         = whoisResolver;
        _hostingTypeResolver   = hostingTypeResolver   ?? throw new ArgumentNullException(nameof(hostingTypeResolver));
        _dnsResolver           = dnsResolver           ?? throw new ArgumentNullException(nameof(dnsResolver));
        _geolocator            = geolocator;
        _reputationChecker     = reputationChecker;
        _forceWhois            = forceWhois;
    }

    public async Task<ClassificationResult> ClassifyAsync(string ipAddress, CancellationToken cancellationToken = default)
    {
        // PTR and geolocation run in parallel with core classification.
        Task<string?> ptrTask = IPAddress.TryParse(ipAddress, out var parsedIp)
            ? _dnsResolver.ReverseDnsAsync(parsedIp, cancellationToken)
            : Task.FromResult<string?>(null);
        Task<GeoLocation?> geoTask = _geolocator != null
            ? _geolocator.LocateAsync(ipAddress, cancellationToken)
            : Task.FromResult<GeoLocation?>(null);

        var core = await ClassifyCoreAsync(ipAddress, cancellationToken);
        string? ptr         = await ptrTask;
        GeoLocation? geo    = await geoTask;

        bool isHosting = core.IsHosting;

        // Router PTR (e.g. ae2.cr6-cph1.ip4.gtt.net) → backbone infrastructure IP, not rentable hosting.
        bool routerDowngraded = false;
        if (isHosting && ClassificationRules.IsRouterPtr(ptr))
        {
            isHosting = false;
            routerDowngraded = true;
        }

        // PTR upgrade: if core classification missed hosting but PTR explicitly indicates
        // a cloud/VPS instance (instance337049.*, vm-42.*) — treat as hosting.
        // Skip upgrade if router-downgrade already determined this is infrastructure.
        HostingType? ptrHostingType = null;
        string? ptrWebsite = null;
        if (!isHosting && !routerDowngraded)
        {
            ptrHostingType = ClassificationRules.ResolveHostingTypeFromPtr(ptr);
            if (ptrHostingType != null)
            {
                isHosting = true;
                // Core skipped website lookup (isHosting was false at that point). Resolve it here.
                if (string.IsNullOrWhiteSpace(core.Website) && core.Asn.HasValue)
                {
                    ptrWebsite = _websiteResolver.GetWebsite(core.Asn, core.Organization);
                    if (string.IsNullOrWhiteSpace(ptrWebsite))
                        ptrWebsite = await _websiteResolver.GetWebsiteFromPeeringDbAsync(
                            core.Asn.Value, cancellationToken);
                }
            }
        }

        // Country: prefer DB-IP (physical location) over ip2asn (ASN owner jurisdiction).
        string? country = geo?.Country ?? core.Country;

        return core with
        {
            IsHosting   = isHosting,
            HostingType = isHosting ? (ptrHostingType ?? core.HostingType) : core.HostingType,
            Website     = core.Website ?? ptrWebsite,
            Ptr        = ptr,
            Country    = country,
            City       = geo?.City,
            Region     = geo?.Region,
            Latitude   = geo?.Latitude,
            Longitude  = geo?.Longitude,
            Timezone   = geo?.Timezone,
        };
    }

    private async Task<ClassificationResult> ClassifyCoreAsync(string ipAddress, CancellationToken cancellationToken)
    {
        try
        {
            uint ipInt = IpConverter.IpToUint(ipAddress);

            // Reputation — O(1) dictionary lookup, performed immediately.
            int? reputation = _reputationChecker?.Check(ipInt);

            // 1. Диапазоны хостингов
            var hostingRange = _hostingRangeProvider.Find(ipInt);
            if (hostingRange.HasValue)
            {
                var hr  = hostingRange.Value;
                var rec = _ipIndex.Find(ipInt);
                uint? asn = rec.HasValue && rec.Value.Asn > 0 ? rec.Value.Asn : null;

                var hostingType = await _hostingTypeResolver.ResolveAsync(
                    ipAddress, asn, hr.ProviderName, cancellationToken);

                string? website = _websiteResolver.GetWebsite(asn, hr.ProviderName, hr.Website);
                if (string.IsNullOrWhiteSpace(website) && asn.HasValue)
                    website = await _websiteResolver.GetWebsiteFromPeeringDbAsync(asn.Value, cancellationToken);

                string? ipRange = rec.HasValue ? IpConverter.ToCidr(rec.Value.StartIp, rec.Value.EndIp) : null;

                int? peeringCount = null;
                IReadOnlyList<string>? ixLocations = null;
                if (asn.HasValue)
                {
                    var pdbInfo = await _websiteResolver.GetNetworkInfoFromPeeringDbAsync(asn.Value, cancellationToken);
                    peeringCount = pdbInfo?.IxCount;
                    if (pdbInfo?.NetId.HasValue == true)
                        ixLocations = await _websiteResolver.GetIxLocationsAsync(asn.Value, cancellationToken);
                }

                return new ClassificationResult(
                    IsHosting:       true,
                    Asn:             asn,
                    Organization:    hr.ProviderName,
                    Country:         rec.HasValue ? rec.Value.Country : null,
                    Website:         website,
                    Source:          "HostingRangeDB",
                    HostingType:     hostingType,
                    IpRange:         ipRange,
                    ReputationScore: reputation,
                    PeeringCount:    peeringCount,
                    IxLocations:     ixLocations
                );
            }

            // 2. IP2ASN
            var record = _ipIndex.Find(ipInt);
            if (record.HasValue)
            {
                string org     = record.Value.Description;
                uint   asn     = record.Value.Asn;
                string ipRange = IpConverter.ToCidr(record.Value.StartIp, record.Value.EndIp);

                bool isNonHosting = ClassificationRules.IsNonHostingOrg(org)
                                 || ClassificationRules.BackboneAsns.Contains(asn);
                bool isHosting = !isNonHosting
                              && (_hostingAsns.Contains(asn)
                                  || _badAsns.Contains(asn)
                                  || ClassificationRules.KnownHostingOrgs.Contains(org)
                                  || ClassificationRules.HostingKeywords.Any(k =>
                                         org.Contains(k, StringComparison.OrdinalIgnoreCase)));

                if (!isHosting && !isNonHosting && asn > 0)
                {
                    var info = await _websiteResolver.GetNetworkInfoFromPeeringDbAsync(asn, cancellationToken);
                    if (ClassificationRules.IsHostingPeeringDbType(info?.InfoType))
                        isHosting = true;
                }

                DateTime? registrationDate = null;
                DateTime? updatedDate      = null;
                string?   status           = null;
                string?   rir              = null;
                string?   abuseEmail       = null;
                string?   website          = null;
                HostingType? hostingType   = null;

                bool shouldWhois = _forceWhois
                    || (isHosting && !ClassificationRules.KnownHostingOrgs.Contains(org));

                if (shouldWhois && _whoisResolver != null)
                {
                    var whois = await _whoisResolver.ResolveAsync(ipAddress, cancellationToken);
                    if (whois?.Organization != null)
                    {
                        bool orgIsNonHosting = ClassificationRules.IsNonHostingOrg(whois.Organization);
                        if (orgIsNonHosting)
                            isHosting = false;

                        registrationDate = whois.RegistrationDate;
                        updatedDate      = whois.UpdatedDate;
                        status           = whois.Status;
                        rir              = whois.Rir;
                        abuseEmail       = whois.AbuseEmail;

                        if (!orgIsNonHosting)
                        {
                            website = _websiteResolver.GetWebsite(null, whois.Organization, whois.Website);
                            if (string.IsNullOrWhiteSpace(website) && asn > 0)
                                website = await _websiteResolver.GetWebsiteFromPeeringDbAsync(asn, cancellationToken);
                        }
                    }
                }

                int? peeringCount = null;
                IReadOnlyList<string>? ixLocations = null;

                // Tag known CDN ASNs for display even when IsHosting=false.
                if (!isHosting && ClassificationRules.CdnAsns.Contains(asn))
                    hostingType = HostingType.Cdn;

                if (isHosting)
                {
                    hostingType = await _hostingTypeResolver.ResolveAsync(
                        ipAddress, asn, org, cancellationToken);

                    if (string.IsNullOrWhiteSpace(website))
                    {
                        website = _websiteResolver.GetWebsite(asn, org);
                        if (string.IsNullOrWhiteSpace(website) && asn > 0)
                            website = await _websiteResolver.GetWebsiteFromPeeringDbAsync(asn, cancellationToken);
                    }

                    if (asn > 0)
                    {
                        var pdbInfo = await _websiteResolver.GetNetworkInfoFromPeeringDbAsync(asn, cancellationToken);
                        peeringCount = pdbInfo?.IxCount;
                        if (pdbInfo?.NetId.HasValue == true)
                            ixLocations = await _websiteResolver.GetIxLocationsAsync(asn, cancellationToken);
                    }
                }

                return new ClassificationResult(
                    IsHosting:        isHosting,
                    Asn:              asn,
                    Organization:     org,
                    Country:          record.Value.Country,
                    Website:          website,
                    Source:           "IP2ASN",
                    HostingType:      hostingType,
                    RegistrationDate: registrationDate,
                    UpdatedDate:      updatedDate,
                    Status:           status,
                    IpRange:          ipRange,
                    Rir:              rir,
                    AbuseEmail:       abuseEmail,
                    ReputationScore:  reputation,
                    PeeringCount:     peeringCount,
                    IxLocations:      ixLocations
                );
            }

            // 3. WHOIS-фолбэк
            if (_whoisResolver != null)
            {
                var whois = await _whoisResolver.ResolveAsync(ipAddress, cancellationToken);
                if (whois?.Organization != null)
                {
                    if (ClassificationRules.IsNonHostingOrg(whois.Organization))
                        return new ClassificationResult(false, null, whois.Organization, whois.Country, null, "WHOIS",
                            Rir: whois.Rir, AbuseEmail: whois.AbuseEmail, ReputationScore: reputation);

                    bool isHosting = ClassificationRules.KnownHostingOrgs.Contains(whois.Organization)
                                  || ClassificationRules.HostingKeywords.Any(k =>
                                         whois.Organization.Contains(k, StringComparison.OrdinalIgnoreCase));

                    string?      website     = null;
                    HostingType? hostingType = null;

                    if (isHosting)
                    {
                        website     = _websiteResolver.GetWebsite(null, whois.Organization, whois.Website);
                        hostingType = await _hostingTypeResolver.ResolveAsync(
                            ipAddress, null, whois.Organization, cancellationToken);
                    }

                    return new ClassificationResult(
                        IsHosting:        isHosting,
                        Asn:              null,
                        Organization:     whois.Organization,
                        Country:          whois.Country,
                        Website:          website,
                        Source:           "WHOIS",
                        HostingType:      hostingType,
                        RegistrationDate: whois.RegistrationDate,
                        UpdatedDate:      whois.UpdatedDate,
                        Status:           whois.Status,
                        Rir:              whois.Rir,
                        AbuseEmail:       whois.AbuseEmail,
                        ReputationScore:  reputation
                    );
                }
            }

            return new ClassificationResult(false, null, null, null, null, "Unknown");
        }
        catch (OperationCanceledException) { throw; }
        catch (OutOfMemoryException) { throw; }
        catch (Exception ex)
        {
            return new ClassificationResult(false, null, null, null, null, $"Error: {ex.Message}");
        }
    }

    public void Dispose() => _geolocator?.Dispose();
}
