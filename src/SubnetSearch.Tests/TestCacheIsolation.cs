using System.Runtime.CompilerServices;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Tests;

// Redirects all derived caches (hosting index, ip2asn/as.json/ipsum loaders, integrity snapshots,
// LocalHostingAsnCache fallback) into an isolated temp directory for the whole test run, so tests
// never write into the developer's real %LocalAppData%\rover\cache. Runs once, before any
// test, via [ModuleInitializer]; the directory is removed on process exit.
internal static class TestCacheIsolation
{
    [ModuleInitializer]
    internal static void Init()
    {
        // Respect an externally provided override (e.g. CI) instead of clobbering it.
        if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(DerivedCachePath.CacheRootEnvVar)))
            return;

        string dir = Path.Combine(
            Path.GetTempPath(), "rover-test-cache", Guid.NewGuid().ToString("N"));
        Environment.SetEnvironmentVariable(DerivedCachePath.CacheRootEnvVar, dir);

        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
            catch { /* best-effort cleanup */ }
        };
    }
}
