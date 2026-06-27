namespace SubnetSearch.Cli;

public static class DefaultDataPath
{
    /// <summary>
    /// Определяет путь к папке данных в зависимости от окружения.
    /// </summary>
    public static string GetDefaultDataDirectory()
    {
        // Environment variable override — used by Docker, CI, custom installs.
        var envPath = Environment.GetEnvironmentVariable("SUBNETSEARCH_DATA_DIR");
        if (!string.IsNullOrWhiteSpace(envPath))
            return envPath;

        // Development: locate .sln file above the binary.
        string? projectRoot = FindProjectRoot();
        if (projectRoot != null)
            return Path.Combine(projectRoot, "data");

        // Production: user profile directory.
        var basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(basePath, "SubnetSearch", "data");
    }

    /// <summary>
    /// Ищет корень проекта, поднимаясь от исполняемого файла и проверяя наличие .sln или .csproj.
    /// </summary>
    private static string? FindProjectRoot()
{
    var directory = AppContext.BaseDirectory;
    while (directory != null)
    {
        if (Directory.GetFiles(directory, "*.sln").Length > 0)
        {
            return directory; // возвращаем директорию с .sln
        }
        var parent = Directory.GetParent(directory);
        directory = parent?.FullName;
    }
    return null;
}
}