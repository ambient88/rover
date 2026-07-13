using System.Text.RegularExpressions;
using System.Text;
using System.Net;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Network.Recommend;

public static class IpListAnalyzer
{
    private static readonly Regex IPv4Regex = new(
        @"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        RegexOptions.Compiled);

    public static IReadOnlyList<string> ExtractIps(string text)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var addresses = new List<string>();

        for (var match = IPv4Regex.Match(text); match.Success; match = match.NextMatch())
        {
            if (!seen.Add(match.Value)) continue;
            addresses.Add(match.Value);
        }

        return addresses;
    }

    // Per-attempt timeout: a DPI-blackholed host (SYN dropped) must not hang the run
    // for HttpClient's default 100s before the second route even gets a chance.
    private static readonly TimeSpan FetchAttemptTimeout = TimeSpan.FromSeconds(20);

    // Reads text from a local file path or HTTP/HTTPS URL.
    // Automatically rewrites GitHub blob URLs to raw.githubusercontent.com.
    //
    // Двухмаршрутная загрузка URL (зеркало стратегии AppBootstrap для data-файлов):
    // основной клиент — bypass-VPN (привязан к физическому интерфейсу), fallbackHttp —
    // системный маршрут (VPN, если активен). Один маршрут не покрывает оба случая:
    // провайдер блокирует часть хостов напрямую (raw.githubusercontent.com — SYN
    // blackhole, «The SSL connection could not be established»), а часть хостов
    // блокирует выходные адреса VPN.
    public static async Task<string> ReadSourceAsync(
        string pathOrUrl, HttpClient http, CancellationToken ct = default,
        HttpClient? fallbackHttp = null)
    {
        if (pathOrUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            pathOrUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            // Block direct IP URLs to prevent SSRF against internal/cloud metadata endpoints.
            // (e.g. 169.254.169.254 AWS metadata, 192.168.x.x internal network)
            var uri = new Uri(pathOrUrl);
            if (uri.HostNameType == UriHostNameType.IPv4 || uri.HostNameType == UriHostNameType.IPv6)
                throw new ArgumentException(
                    $"--from does not accept direct IP URLs to prevent SSRF. Use a hostname instead.");

            var url = RewriteGitHubUrl(pathOrUrl);
            try
            {
                return await FetchWithTimeoutAsync(http, url, ct);
            }
            // Сетевой сбой первой попытки (включая её 20с-таймаут) → вторая попытка
            // другим маршрутом. Отмена пользователем (Ctrl+C) не перехватывается.
            catch (Exception ex) when (
                fallbackHttp != null && !ct.IsCancellationRequested &&
                ex is HttpRequestException or OperationCanceledException)
            {
                return await FetchWithTimeoutAsync(
                    fallbackHttp, url, ct, validateDestinations: true);
            }
        }

        // Resolve to absolute path to expose any traversal attempts in error messages,
        // then restrict to .txt and .csv extensions to limit accidental exposure of
        // config files or credentials when used in scripts/CI pipelines.
        var fullPath = Path.GetFullPath(pathOrUrl);
        var ext = Path.GetExtension(fullPath).ToLowerInvariant();
        if (ext is not ".txt" and not ".csv")
            throw new ArgumentException(
                $"--from supports only .txt and .csv files, got: {ext}");

        return await File.ReadAllTextAsync(fullPath, ct);
    }

    public static async Task<IReadOnlyList<string>> ReadIpsAsync(
        string pathOrUrl,
        HttpClient http,
        CancellationToken ct = default,
        HttpClient? fallbackHttp = null)
    {
        if (pathOrUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || pathOrUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            var uri = new Uri(pathOrUrl);
            if (uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6)
                throw new ArgumentException(
                    "--from does not accept direct IP URLs to prevent SSRF. Use a hostname instead.");

            string url = RewriteGitHubUrl(pathOrUrl);
            try
            {
                return await ReadHttpIpsAsync(http, url, ct, validateDestinations: false);
            }
            catch (Exception ex) when (
                fallbackHttp != null && !ct.IsCancellationRequested
                && ex is HttpRequestException or OperationCanceledException)
            {
                return await ReadHttpIpsAsync(
                    fallbackHttp, url, ct, validateDestinations: true);
            }
        }

        string fullPath = ValidateLocalSourcePath(pathOrUrl);
        await using var stream = new FileStream(
            fullPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 65_536, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var reader = new StreamReader(stream);
        return await ExtractIpsAsync(reader, ct);
    }

    private static async Task<string> FetchWithTimeoutAsync(
        HttpClient http,
        string url,
        CancellationToken ct,
        bool validateDestinations = false)
    {
        using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        attemptCts.CancelAfter(FetchAttemptTimeout);
        Uri current = new(url);
        for (int redirect = 0; redirect <= 10; redirect++)
        {
            if (validateDestinations)
                await EnsurePublicDestinationAsync(current, attemptCts.Token);
            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            using var response = await http.SendAsync(
                request,
                HttpCompletionOption.ResponseContentRead,
                attemptCts.Token);
            if (IsRedirect(response) && response.Headers.Location != null)
            {
                current = ResolveRedirect(current, response.Headers.Location);
                continue;
            }
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync(attemptCts.Token);
        }
        throw new HttpRequestException("Too many redirects while loading --from source.");
    }

    private static async Task<IReadOnlyList<string>> ReadHttpIpsAsync(
        HttpClient http,
        string url,
        CancellationToken ct,
        bool validateDestinations)
    {
        using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        attemptCts.CancelAfter(FetchAttemptTimeout);
        Uri current = new(url);
        for (int redirect = 0; redirect <= 10; redirect++)
        {
            if (validateDestinations)
                await EnsurePublicDestinationAsync(current, attemptCts.Token);
            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            using var response = await http.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, attemptCts.Token);
            if (IsRedirect(response) && response.Headers.Location != null)
            {
                current = ResolveRedirect(current, response.Headers.Location);
                continue;
            }
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(attemptCts.Token);
            using var reader = new StreamReader(stream);
            return await ExtractIpsAsync(reader, attemptCts.Token);
        }
        throw new HttpRequestException("Too many redirects while loading --from source.");
    }

    private static async Task EnsurePublicDestinationAsync(Uri uri, CancellationToken ct)
    {
        if (uri.Scheme is not "http" and not "https")
            throw new ArgumentException("--from redirects must use HTTP or HTTPS.");
        IPAddress[] addresses = await Dns.GetHostAddressesAsync(uri.Host, ct);
        if (addresses.Length == 0 || addresses.Any(address => !IsPublicAddress(address)))
            throw new ArgumentException("--from URL resolves to a private or reserved address.");
    }

    private static bool IsRedirect(HttpResponseMessage response)
        => (int)response.StatusCode is 301 or 302 or 303 or 307 or 308;

    private static Uri ResolveRedirect(Uri current, Uri location)
        => location.IsAbsoluteUri ? location : new Uri(current, location);

    private static string ValidateLocalSourcePath(string pathOrUrl)
    {
        string fullPath = Path.GetFullPath(pathOrUrl);
        string extension = Path.GetExtension(fullPath).ToLowerInvariant();
        if (extension is not ".txt" and not ".csv")
            throw new ArgumentException(
                $"--from supports only .txt and .csv files, got: {extension}");
        return fullPath;
    }

    internal static async Task<IReadOnlyList<string>> ExtractIpsAsync(
        TextReader reader,
        CancellationToken ct = default)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<string>();
        var token = new StringBuilder(16);
        char[] buffer = new char[65_536];
        bool overflow = false;
        bool startsAtBoundary = true;
        char previous = '\0';

        while (true)
        {
            int read = await reader.ReadAsync(buffer.AsMemory(), ct);
            if (read == 0) break;
            for (int i = 0; i < read; i++)
            {
                char value = buffer[i];
                if (char.IsAsciiDigit(value) || value == '.')
                {
                    if (token.Length == 0)
                        startsAtBoundary = !IsWordCharacter(previous);
                    if (token.Length < 64)
                        token.Append(value);
                    else
                        overflow = true;
                }
                else
                {
                    FlushToken(value);
                }
                previous = value;
            }
        }
        FlushToken('\0');
        return result;

        void FlushToken(char next)
        {
            if (!overflow && startsAtBoundary && !IsWordCharacter(next)
                && IsValidIpv4Token(token))
            {
                string address = token.ToString();
                if (seen.Add(address)) result.Add(address);
            }
            token.Clear();
            overflow = false;
            startsAtBoundary = true;
        }
    }

    private static bool IsWordCharacter(char value)
        => char.IsLetterOrDigit(value) || value == '_';

    private static bool IsValidIpv4Token(StringBuilder token)
    {
        if (token.Length is < 7 or > 15) return false;
        int parts = 0;
        int value = 0;
        int digits = 0;
        for (int i = 0; i <= token.Length; i++)
        {
            if (i < token.Length && token[i] != '.')
            {
                if (!char.IsAsciiDigit(token[i]) || ++digits > 3) return false;
                value = value * 10 + token[i] - '0';
                if (value > 255) return false;
                continue;
            }
            if (digits == 0) return false;
            parts++;
            value = 0;
            digits = 0;
        }
        return parts == 4;
    }

    internal static bool IsPublicAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.None) ||
            address.Equals(IPAddress.IPv6None))
        {
            return false;
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            byte first = address.GetAddressBytes()[0];
            return !address.IsIPv6LinkLocal && !address.IsIPv6SiteLocal &&
                   !address.IsIPv6Multicast && (first & 0xFE) != 0xFC;
        }

        byte[] bytes = address.GetAddressBytes();
        byte firstOctet = bytes[0];
        byte secondOctet = bytes[1];
        if (firstOctet is 0 or 10 or 127) return false;
        if (firstOctet == 100 && secondOctet is >= 64 and <= 127) return false;
        if (firstOctet == 169 && secondOctet == 254) return false;
        if (firstOctet == 172 && secondOctet is >= 16 and <= 31) return false;
        if (firstOctet == 192 && secondOctet == 168) return false;
        if (firstOctet == 198 && secondOctet is 18 or 19) return false;
        if (firstOctet >= 224) return false;
        return true;
    }

    // Rewrites GitHub blob URLs to raw format so we get plain text, not HTML.
    // https://github.com/user/repo/blob/branch/file → https://raw.githubusercontent.com/user/repo/branch/file
    internal static string RewriteGitHubUrl(string url)
    {
        var match = Regex.Match(url,
            @"^https?://github\.com/([^/]+/[^/]+)/blob/(.+)$",
            RegexOptions.IgnoreCase);
        if (match.Success)
            return $"https://raw.githubusercontent.com/{match.Groups[1].Value}/{match.Groups[2].Value}";
        return url;
    }

    // Maps IPs to ASNs via ip2asn index, returns list sorted by coverage descending.
    // Private and reserved IPs are skipped.
    public static IReadOnlyList<(uint Asn, int Count)> AggregateByAsn(
        IReadOnlyList<string> ips, IIpRangeIndex ipIndex)
    {
        var counts = new Dictionary<uint, int>();
        foreach (var ip in ips)
        {
            if (!IpConverter.TryIpToUint(ip, out uint ipUint)) continue;
            if (IsPrivateOrReserved(ipUint)) continue;
            var rec = ipIndex.Find(ipUint);
            if (!rec.HasValue || rec.Value.Asn == 0) continue;
            counts[rec.Value.Asn] = counts.GetValueOrDefault(rec.Value.Asn) + 1;
        }
        return [.. counts.OrderByDescending(kv => kv.Value).Select(kv => (kv.Key, kv.Value))];
    }

    private static bool IsPrivateOrReserved(uint ip)
    {
        // 0.0.0.0/8 — IANA reserved "this" network
        if ((ip & 0xFF000000u) == 0x00000000u) return true;
        // 10.0.0.0/8 — RFC 1918 private
        if ((ip & 0xFF000000u) == 0x0A000000u) return true;
        // 100.64.0.0/10 — CGNAT (RFC 6598)
        if ((ip & 0xFFC00000u) == 0x64400000u) return true;
        // 127.0.0.0/8 — loopback
        if ((ip & 0xFF000000u) == 0x7F000000u) return true;
        // 169.254.0.0/16 — link-local (also AWS/GCP instance metadata endpoint)
        if ((ip & 0xFFFF0000u) == 0xA9FE0000u) return true;
        // 172.16.0.0/12 — RFC 1918 private
        if ((ip & 0xFFF00000u) == 0xAC100000u) return true;
        // 192.168.0.0/16 — RFC 1918 private
        if ((ip & 0xFFFF0000u) == 0xC0A80000u) return true;
        // 198.51.100.0/24 — TEST-NET-2 (RFC 5737 documentation)
        if ((ip & 0xFFFFFF00u) == 0xC6336400u) return true;
        // 203.0.113.0/24 — TEST-NET-3 (RFC 5737 documentation)
        if ((ip & 0xFFFFFF00u) == 0xCB007100u) return true;
        // 255.255.255.255 — broadcast
        if (ip == 0xFFFFFFFFu) return true;
        return false;
    }
}
