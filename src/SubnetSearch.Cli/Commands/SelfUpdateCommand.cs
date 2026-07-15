using System.Runtime.InteropServices;
using SubnetSearch.Data;

namespace SubnetSearch.Cli.Commands;

// Replaces the running single-file binary with the latest GitHub release.
// apt installations should keep using `apt upgrade`; this command targets the
// install.sh and manual-download channels that have no package manager.
public static class SelfUpdateCommand
{
    public static async Task<int> ExecuteAsync(CancellationToken ct)
    {
        string current = HelpText.CurrentVersion;
        AnsiConsole.MarkupLine($"Current version: [bold]v{Markup.Escape(current)}[/]");

        using var http = new HttpClient();
        var releases = new GitHubReleaseClient(http);
        var latest = await releases.GetLatestAsync(ct);
        if (latest == null)
        {
            AnsiConsole.MarkupLine("[red]Could not reach GitHub to check for releases. Try again later.[/]");
            return 1;
        }

        if (!GitHubReleaseClient.IsNewer(latest.Version, current))
        {
            AnsiConsole.MarkupLine($"[green]Already up to date[/] (latest release: v{Markup.Escape(latest.Version)}).");
            return 0;
        }

        string? exePath = Environment.ProcessPath;
        if (exePath == null
            || Path.GetFileNameWithoutExtension(exePath).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        {
            AnsiConsole.MarkupLine(
                "[yellow]self-update works only for the published rover binary. " +
                "Development builds update through git.[/]");
            return 1;
        }

        string? assetName = GitHubReleaseClient.AssetName(CurrentOsTag(), RuntimeInformation.OSArchitecture);
        if (assetName == null || !latest.AssetUrls.TryGetValue(assetName, out var downloadUrl))
        {
            AnsiConsole.MarkupLine(
                $"[red]Release v{Markup.Escape(latest.Version)} has no binary for this platform. " +
                "Download it manually from github.com/ambient88/rover/releases.[/]");
            return 1;
        }

        AnsiConsole.MarkupLine($"Downloading [bold]v{Markup.Escape(latest.Version)}[/] ({Markup.Escape(assetName)})...");

        // Stage next to the current binary so the final move stays on one volume (atomic).
        string newPath = exePath + ".new";
        string oldPath = exePath + ".old";
        try
        {
            await using (var target = File.Create(newPath))
            await using (var source = await http.GetStreamAsync(downloadUrl, ct))
            {
                await source.CopyToAsync(target, ct);
            }

            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(newPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                    UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                    UnixFileMode.OtherRead | UnixFileMode.OtherExecute);

            // Windows cannot overwrite a running executable, but it can be renamed;
            // the leftover .old file is cleaned up by the next self-update run.
            if (File.Exists(oldPath)) File.Delete(oldPath);
            if (OperatingSystem.IsWindows())
            {
                File.Move(exePath, oldPath);
                File.Move(newPath, exePath);
            }
            else
            {
                File.Move(newPath, exePath, overwrite: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or HttpRequestException)
        {
            try { if (File.Exists(newPath)) File.Delete(newPath); } catch { }
            AnsiConsole.MarkupLine($"[red]Update failed: {Markup.Escape(ex.Message)}[/]");
            if (ex is UnauthorizedAccessException)
                AnsiConsole.MarkupLine("[yellow]The install location may require elevated rights (try sudo).[/]");
            return 1;
        }

        AnsiConsole.MarkupLine($"[green]Updated to v{Markup.Escape(latest.Version)}.[/]");
        return 0;
    }

    private static string? CurrentOsTag()
        => OperatingSystem.IsWindows() ? "win"
         : OperatingSystem.IsLinux()   ? "linux"
         : OperatingSystem.IsMacOS()   ? "osx"
         : null;
}
