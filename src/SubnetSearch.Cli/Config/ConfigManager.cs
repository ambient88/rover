using System.Text.Json;

namespace SubnetSearch.Cli.Config;

public static class ConfigManager
{
    private static string ConfigPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "subnetSearch", "config.json");

    public static AppConfig Load()
    {
        try
        {
            if (!File.Exists(ConfigPath)) return new AppConfig();
            var json = File.ReadAllText(ConfigPath);
            return JsonSerializer.Deserialize<AppConfig>(json) ?? new AppConfig();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return new AppConfig();
        }
    }

    public static void SetKey(string service, string value)
    {
        var config = Load();
        ApplyKey(config, service, value);
        Save(config);
        Console.WriteLine($"Key for '{service}' saved to {ConfigPath}");
    }

    public static void UnsetKey(string service)
    {
        var config = Load();
        switch (service.ToLowerInvariant())
        {
            case "abuseipdb":  config.AbuseIpDbKey = null; break;
            case "greynoise":  config.GreyNoiseKey  = null; break;
            case "peeringdb":  config.PeeringDbKey  = null; break;
            default: throw new ArgumentException(
                $"Unknown service '{service}'. Valid: abuseipdb, greynoise, peeringdb");
        }
        Save(config);
        Console.WriteLine($"Key for '{service}' removed.");
    }

    public static void ListKeys()
    {
        var config = Load();
        Console.WriteLine($"Config file: {ConfigPath}");
        Console.WriteLine();
        PrintEntry("abuseipdb", config.AbuseIpDbKey);
        PrintEntry("greynoise", config.GreyNoiseKey);
        PrintEntry("peeringdb", config.PeeringDbKey);

        static void PrintEntry(string name, string? value)
        {
            if (value is null)
                Console.WriteLine($"  {name,-12} not set");
            else
                Console.WriteLine($"  {name,-12} {MaskKey(value)}");
        }

        static string MaskKey(string key) =>
            key.Length > 20 ? key[..3] + new string('*', key.Length - 3) : new string('*', key.Length);
    }

    // Applies an inline key override without writing to disk.
    public static void ApplyInline(AppConfig config, string service, string value)
        => ApplyKey(config, service, value);

    private static void ApplyKey(AppConfig config, string service, string value)
    {
        switch (service.ToLowerInvariant())
        {
            case "abuseipdb":  config.AbuseIpDbKey = value; break;
            case "greynoise":  config.GreyNoiseKey  = value; break;
            case "peeringdb":  config.PeeringDbKey  = value; break;
            default: throw new ArgumentException(
                $"Unknown service '{service}'. Valid: abuseipdb, greynoise, peeringdb");
        }
    }

    private static void Save(AppConfig config)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
        // API keys are stored in plain text in the user's AppData directory.
        // This is standard CLI practice; keys are masked when listed (--list-keys).
        // Users on shared machines should use --peeringdb-key / --abuseipdb-key inline flags instead.
        File.WriteAllText(ConfigPath,
            JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
    }
}
