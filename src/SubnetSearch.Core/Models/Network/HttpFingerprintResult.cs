namespace SubnetSearch.Core.Models.Network;

public record HttpFingerprintResult(
    string?                               CdnProvider,
    string?                               CdnProduct,
    string?                               ServerHeader,
    string?                               XPoweredBy,
    bool?                                 HttpsRedirect,
    string?                               TlsIssuer,
    DateTime?                             TlsExpiry,
    IReadOnlyList<string>?                TlsSans,
    string?                               TlsVersion,
    bool?                                 TlsExpired,
    // Proxy/CDN indicator headers found in the HTTP response.
    IReadOnlyDictionary<string, string>?  ProxyHeaders = null
);
