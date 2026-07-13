using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Cli;

public static class ArgsParser
{
    private static readonly string[] KnownModes = ["-a", "-d", "-c", "-l", "-o", "-r", "update"];

    public static string? GetArgValue(string[] args, string flag)
    {
        var idx = Array.IndexOf(args, flag);
        return idx >= 0 && idx + 1 < args.Length ? args[idx + 1] : null;
    }

    // Validates mode and flags BEFORE data downloads. Returns (true, null) if valid.
    public static (bool Valid, string? Error) Validate(string[] args)
    {
        if (args.Length == 0) return (true, null);

        string mode = args.Select(a => a.ToLowerInvariant())
                          .FirstOrDefault(a => KnownModes.Contains(a))
                      ?? args[0].ToLower();

        // Modes that require a positional argument
        if (mode is "-a" or "-d" or "-c" or "-l" or "-o")
        {
            var modeIdx = Array.FindIndex(args, a => a.ToLower() == mode);
            string arg  = modeIdx + 1 < args.Length ? args[modeIdx + 1] : string.Empty;
            if (string.IsNullOrWhiteSpace(arg) || arg.StartsWith('-'))
            {
                string name = mode switch {
                    "-a" => "IP address",
                    "-d" => "domain",
                    "-c" => "CIDR range",
                    "-l" => "file path",
                    "-o" => "ASN or provider name",
                    _    => "argument"
                };
                return (false, $"{mode} requires a {name}.");
            }
        }

        if (mode == "-r")
        {
            string? typeFilter = GetArgValue(args, "--type");
            if (typeFilter != null && ProviderFinder.ResolveInfoTypes(typeFilter) == null)
                return (false,
                    $"Unknown --type value: '{typeFilter}'.\n" +
                    $"Valid values:\n  {ProviderFinder.ValidTypeValues}");

            string? maxPingStr = GetArgValue(args, "--max-ping");
            if (maxPingStr != null && (!int.TryParse(maxPingStr, out int mp) || mp < 1))
                return (false, $"--max-ping must be a positive integer, got: '{maxPingStr}'");

            string? topStr = GetArgValue(args, "--top");
            if (topStr != null && (!int.TryParse(topStr, out int top) || top < 1))
                return (false, $"--top must be a positive integer, got: '{topStr}'");

            string? sortBy = GetArgValue(args, "--sort");
            string[] validSorts = ["score", "coverage", "latency", "rpki", "size", "peering", "upstream"];
            if (sortBy != null && !validSorts.Contains(sortBy.ToLowerInvariant()))
                return (false,
                    $"Unknown --sort value: '{sortBy}'.\n" +
                    $"Valid values: {string.Join(", ", validSorts)}");

            string? fromSource = GetArgValue(args, "--from");
            if (fromSource != null
                && !fromSource.StartsWith("http://",  StringComparison.OrdinalIgnoreCase)
                && !fromSource.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                && !File.Exists(fromSource))
                return (false, $"--from: file not found: '{fromSource}'");

            string? countryArg = GetArgValue(args, "--country");
            if (countryArg != null)
            {
                var codes = countryArg.Split(',',
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                foreach (var code in codes)
                {
                    if (code.Length != 2 || !code.All(char.IsLetter))
                        return (false,
                            $"--country: '{code}' is not a valid ISO 3166-1 alpha-2 code " +
                            $"(2 letters, e.g. US, DE, GB).");
                }
            }

            string? preset = GetArgValue(args, "--preset");
            string[] validPresets = ["balanced", "performance", "security"];
            if (preset != null && !validPresets.Contains(preset.ToLowerInvariant()))
                return (false,
                    $"Unknown --preset value: '{preset}'.\n" +
                    $"Valid values: {string.Join(", ", validPresets)}");
        }

        // Catch-all for unknown modes (not a flag either)
        if (!KnownModes.Contains(mode))
            return (false, $"Unknown mode: '{args[0]}'");

        return (true, null);
    }

    public static int FindModeIndex(string[] args)
        => Array.FindIndex(args, arg => KnownModes.Contains(arg.ToLowerInvariant()));
}
