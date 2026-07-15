using System.Runtime.InteropServices;
using System.Text.Json;

namespace SubnetSearch.Data;

/// <summary>Latest published release: a normalized version plus asset download URLs by name.</summary>
public sealed record LatestRelease(string Version, IReadOnlyDictionary<string, string> AssetUrls);

// Queries the GitHub Releases API for the newest published version. Used by the
// `update` version notice and by `self-update`. Every failure degrades to null:
// release checks are auxiliary and must never break the primary command.
public class GitHubReleaseClient(HttpClient http, string repo = GitHubReleaseClient.DefaultRepo)
{
    public const string DefaultRepo = "ambient88/rover";

    public async Task<LatestRelease?> GetLatestAsync(CancellationToken ct = default)
    {
        try
        {
            using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            reqCts.CancelAfter(TimeSpan.FromSeconds(4));
            using var req = new HttpRequestMessage(
                HttpMethod.Get, $"https://api.github.com/repos/{repo}/releases/latest");
            req.Headers.TryAddWithoutValidation("Accept", "application/vnd.github+json");
            // The GitHub API rejects requests without a User-Agent.
            req.Headers.TryAddWithoutValidation("User-Agent", DownloadManagerFactory.UserAgent);

            using var resp = await http.SendAsync(req, reqCts.Token);
            if (!resp.IsSuccessStatusCode) return null;

            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(reqCts.Token));
            var root = doc.RootElement;
            if (!root.TryGetProperty("tag_name", out var tagEl)
                || tagEl.GetString() is not { Length: > 0 } tag)
                return null;

            var assets = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (root.TryGetProperty("assets", out var assetsEl)
                && assetsEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var asset in assetsEl.EnumerateArray())
                {
                    if (asset.TryGetProperty("name", out var nameEl)
                        && asset.TryGetProperty("browser_download_url", out var urlEl)
                        && nameEl.GetString() is { Length: > 0 } name
                        && urlEl.GetString() is { Length: > 0 } url)
                    {
                        assets[name] = url;
                    }
                }
            }

            return new LatestRelease(NormalizeVersion(tag), assets);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    // "v1.2.3-alpha.0+abc1234" -> "1.2.3" (bare numeric core for Version.TryParse).
    internal static string NormalizeVersion(string tag)
    {
        var version = tag.Trim();
        if (version.StartsWith('v') || version.StartsWith('V'))
            version = version[1..];
        int cut = version.IndexOfAny(['-', '+']);
        return cut >= 0 ? version[..cut] : version;
    }

    // True only when both versions parse and the latest one is strictly higher,
    // so garbage input can never produce a false "new version" nudge.
    public static bool IsNewer(string latest, string current)
        => Version.TryParse(NormalizeVersion(latest), out var latestVersion)
        && Version.TryParse(NormalizeVersion(current), out var currentVersion)
        && latestVersion > currentVersion;

    // Release asset naming mirrors .github/workflows/release.yml:
    // rover-{win|linux|osx}-{x64|arm64}, with .exe on Windows.
    // The caller supplies the OS tag so this stays a pure, testable mapping.
    public static string? AssetName(string? osTag, Architecture arch)
    {
        if (osTag is not ("win" or "linux" or "osx")) return null;
        string? archTag = arch switch
        {
            Architecture.X64   => "x64",
            Architecture.Arm64 => "arm64",
            _                  => null,
        };
        if (archTag == null) return null;
        return $"rover-{osTag}-{archTag}{(osTag == "win" ? ".exe" : "")}";
    }
}
