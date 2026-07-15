namespace SubnetSearch.Cli;

public static class DefaultDataPath
{
    /// <summary>
    /// Determines the data directory path based on the environment.
    /// </summary>
    public static string GetDefaultDataDirectory()
    {
        // Docker, CI, and custom installations can override the path with an environment variable.
        var envPath = Environment.GetEnvironmentVariable("ROVER_DATA_DIR");
        if (!string.IsNullOrWhiteSpace(envPath))
            return envPath;

        // Development: locate .sln file above the binary.
        string? projectRoot = FindProjectRoot();
        if (projectRoot != null)
            return Path.Combine(projectRoot, "data");

        // Production: user profile directory.
        var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(basePath, "rover", "data");
    }

    /// <summary>
    /// Finds the project root by walking up from the executable and checking for a .sln or .csproj.
    /// </summary>
    private static string? FindProjectRoot()
{
    var directory = AppContext.BaseDirectory;
    while (directory != null)
    {
        if (Directory.GetFiles(directory, "*.sln").Length > 0)
        {
            return directory; // return the directory that contains the .sln
        }
        var parent = Directory.GetParent(directory);
        directory = parent?.FullName;
    }
    return null;
}
}
