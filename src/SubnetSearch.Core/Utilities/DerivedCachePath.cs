using System.Security.Cryptography;
using System.Text;

namespace SubnetSearch.Core.Utilities;

public static class DerivedCachePath
{
    // Optional override for the derived-cache root. Lets CI and the test suite redirect caches
    // away from the user's LocalApplicationData (which tests would otherwise pollute).
    public const string CacheRootEnvVar = "ROVER_CACHE_DIR";

    public static string ForDataDirectory(string dataDirectory, string category)
        => ForDataDirectory(
            dataDirectory,
            category,
            Environment.GetEnvironmentVariable(CacheRootEnvVar),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));

    // Pure path resolution, separated from process state so every branch is unit-testable.
    internal static string ForDataDirectory(
        string dataDirectory, string category, string? overrideRoot, string localData)
    {
        string source = Path.GetFullPath(dataDirectory);
        string hash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(source)))[..16];

        string root;
        if (!string.IsNullOrWhiteSpace(overrideRoot))
        {
            root = overrideRoot;
        }
        else
        {
            if (string.IsNullOrWhiteSpace(localData))
                localData = Path.GetTempPath();
            root = Path.Combine(localData, "rover", "cache");
        }

        return Path.Combine(root, hash, category);
    }
}
