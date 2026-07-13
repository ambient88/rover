using System.Security.Cryptography;
using System.Text;

namespace SubnetSearch.Core.Utilities;

public static class DerivedCachePath
{
    // Optional override for the derived-cache root. Lets CI and the test suite redirect caches
    // away from the user's LocalApplicationData (which tests would otherwise pollute).
    public const string CacheRootEnvVar = "SUBNETSEARCH_CACHE_DIR";

    public static string ForDataDirectory(string dataDirectory, string category)
    {
        string source = Path.GetFullPath(dataDirectory);
        string hash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(source)))[..16];

        string root;
        string? overrideRoot = Environment.GetEnvironmentVariable(CacheRootEnvVar);
        if (!string.IsNullOrWhiteSpace(overrideRoot))
        {
            root = overrideRoot;
        }
        else
        {
            string localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(localData))
                localData = Path.GetTempPath();
            root = Path.Combine(localData, "SubnetSearch", "cache");
        }

        return Path.Combine(root, hash, category);
    }
}
