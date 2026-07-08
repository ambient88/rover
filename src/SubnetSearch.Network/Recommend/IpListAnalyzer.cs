using System.Text.RegularExpressions;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Network.Recommend;

public static class IpListAnalyzer
{
    private static readonly Regex IPv4Regex = new(
        @"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        RegexOptions.Compiled);

    // Extracts unique IPv4 addresses from arbitrary text (one file may contain thousands).
    public static IReadOnlyList<string> ExtractIps(string text)
        => IPv4Regex.Matches(text)
            .Select(m => m.Value)
            .Distinct()
            .ToList();

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
                return await FetchWithTimeoutAsync(fallbackHttp, url, ct);
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

    private static async Task<string> FetchWithTimeoutAsync(
        HttpClient http, string url, CancellationToken ct)
    {
        using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        attemptCts.CancelAfter(FetchAttemptTimeout);
        return await http.GetStringAsync(url, attemptCts.Token);
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
