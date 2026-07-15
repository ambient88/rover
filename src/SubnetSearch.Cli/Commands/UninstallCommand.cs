using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Cli.Commands;

// Removes everything rover wrote to the machine outside of its own binary:
// downloaded data files, derived caches, and the configuration (API keys).
// The binary itself is channel-specific, so the command prints how to remove it.
public static class UninstallCommand
{
    public static int Execute(string[] args)
    {
        bool assumeYes = args.Contains("--yes") || args.Contains("-y");

        var targets = CollectTargets().Where(Directory.Exists).ToList();
        if (targets.Count == 0)
        {
            AnsiConsole.MarkupLine("Nothing to remove: no rover data, cache, or config directories found.");
            PrintBinaryHint();
            return 0;
        }

        AnsiConsole.MarkupLine("[yellow]The following directories will be deleted:[/]");
        foreach (var dir in targets)
            AnsiConsole.MarkupLine($"  {Markup.Escape(dir)}");
        Console.WriteLine();

        if (!assumeYes)
        {
            Console.Write("Delete these directories? [y/N] ");
            string answer = Console.ReadLine()?.Trim() ?? "";
            if (!answer.Equals("y", StringComparison.OrdinalIgnoreCase)
                && !answer.Equals("yes", StringComparison.OrdinalIgnoreCase))
            {
                AnsiConsole.MarkupLine("Cancelled. Nothing was deleted.");
                return 1;
            }
        }

        bool allRemoved = true;
        foreach (var dir in targets)
        {
            try
            {
                Directory.Delete(dir, recursive: true);
                AnsiConsole.MarkupLine($"[green]Removed[/] {Markup.Escape(dir)}");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                allRemoved = false;
                AnsiConsole.MarkupLine($"[red]Could not remove[/] {Markup.Escape(dir)}: {Markup.Escape(ex.Message)}");
            }
        }

        Console.WriteLine();
        PrintBinaryHint();
        return allRemoved ? 0 : 1;
    }

    private static IEnumerable<string> CollectTargets()
    {
        // Data files (respects the ROVER_DATA_DIR override, same as the app itself).
        yield return DefaultDataPath.GetDefaultDataDirectory();

        // Derived caches (hosting index, parsed databases, integrity snapshots).
        string? cacheOverride = Environment.GetEnvironmentVariable(DerivedCachePath.CacheRootEnvVar);
        yield return !string.IsNullOrWhiteSpace(cacheOverride)
            ? cacheOverride
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "rover", "cache");

        // Configuration with saved API keys, current and pre-rebrand locations.
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        yield return Path.Combine(appData, "rover");
        yield return Path.Combine(appData, "subnetSearch");
    }

    private static void PrintBinaryHint()
    {
        string binary = Environment.ProcessPath ?? "rover";
        AnsiConsole.MarkupLine("[yellow]To remove the rover binary itself:[/]");
        AnsiConsole.MarkupLine("  apt install:     sudo apt remove rover");
        AnsiConsole.MarkupLine($"  install.sh:      sudo rm {Markup.Escape(binary)}");
        AnsiConsole.MarkupLine($"  manual install:  delete {Markup.Escape(binary)}");
    }
}
