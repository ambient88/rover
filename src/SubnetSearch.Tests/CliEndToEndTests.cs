using System.Diagnostics;
using FluentAssertions;

namespace SubnetSearch.Tests;

// End-to-end CLI tests run the built rover binary as a child process and verify its exit code and output.
// They cover immediate offline paths such as version, help, and argument validation.
public class CliEndToEndTests
{
    // Find rover.exe on Windows or rover.dll on other platforms in the CLI build output.
    private static string LocateCliBinDir()
    {
        // The test output path ends with src/SubnetSearch.Tests/bin/<Config>/net8.0.
        var baseDir = AppContext.BaseDirectory;
        var cliDir = baseDir.Replace(
            $"{Path.DirectorySeparatorChar}SubnetSearch.Tests{Path.DirectorySeparatorChar}",
            $"{Path.DirectorySeparatorChar}SubnetSearch.Cli{Path.DirectorySeparatorChar}");
        if (Directory.Exists(cliDir) &&
            (File.Exists(Path.Combine(cliDir, "rover.dll")) || File.Exists(Path.Combine(cliDir, "rover.exe"))))
            return cliDir;

        // Fall back to the newest rover.dll under the CLI project build directory.
        var cliBinRoot = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "SubnetSearch.Cli", "bin"));
        if (Directory.Exists(cliBinRoot))
        {
            var dll = Directory.EnumerateFiles(cliBinRoot, "rover.dll", SearchOption.AllDirectories)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault();
            if (dll != null) return Path.GetDirectoryName(dll)!;
        }
        throw new InvalidOperationException(
            $"rover build output not found (looked in {cliDir} and {cliBinRoot}). " +
            "Ensure the CLI project builds (build-order ProjectReference in the test .csproj).");
    }

    private static (int ExitCode, string Output) RunCli(params string[] args)
    {
        var binDir = LocateCliBinDir();
        var exe = Path.Combine(binDir, "rover.exe");

        ProcessStartInfo psi;
        if (File.Exists(exe))
        {
            psi = new ProcessStartInfo(exe);
            foreach (var a in args) psi.ArgumentList.Add(a);
        }
        else
        {
            psi = new ProcessStartInfo("dotnet");
            psi.ArgumentList.Add(Path.Combine(binDir, "rover.dll"));
            foreach (var a in args) psi.ArgumentList.Add(a);
        }
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError  = true;
        psi.UseShellExecute        = false;
        psi.CreateNoWindow         = true;

        using var p = Process.Start(psi)!;
        string stdout = p.StandardOutput.ReadToEnd();
        string stderr = p.StandardError.ReadToEnd();
        if (!p.WaitForExit(30_000))
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("rover did not exit within 30s");
        }
        return (p.ExitCode, stdout + stderr);
    }

    // Variant with environment overrides and piped stdin for commands that prompt.
    private static (int ExitCode, string Output) RunCliWithEnv(
        IReadOnlyDictionary<string, string> env, string stdin, params string[] args)
    {
        var binDir = LocateCliBinDir();
        var exe = Path.Combine(binDir, "rover.exe");

        ProcessStartInfo psi;
        if (File.Exists(exe))
        {
            psi = new ProcessStartInfo(exe);
            foreach (var a in args) psi.ArgumentList.Add(a);
        }
        else
        {
            psi = new ProcessStartInfo("dotnet");
            psi.ArgumentList.Add(Path.Combine(binDir, "rover.dll"));
            foreach (var a in args) psi.ArgumentList.Add(a);
        }
        foreach (var (key, value) in env)
            psi.Environment[key] = value;
        psi.RedirectStandardInput  = true;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError  = true;
        psi.UseShellExecute        = false;
        psi.CreateNoWindow         = true;

        using var p = Process.Start(psi)!;
        p.StandardInput.Write(stdin);
        p.StandardInput.Close();
        string stdout = p.StandardOutput.ReadToEnd();
        string stderr = p.StandardError.ReadToEnd();
        if (!p.WaitForExit(30_000))
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("rover did not exit within 30s");
        }
        return (p.ExitCode, stdout + stderr);
    }

    [Fact]
    public void Version_PrintsVersionAndExitsZero()
    {
        var (exit, output) = RunCli("--version");

        exit.Should().Be(0);
        output.Should().Contain("rover").And.Contain("0.0.1");
    }

    [Fact]
    public void Help_PrintsUsageAndExitsZero()
    {
        var (exit, output) = RunCli("--help");

        exit.Should().Be(0);
        output.Should().Contain("Usage").And.Contain("-r");
        output.Should().Contain("--preset", "справка перечисляет пресеты рейтинга");
    }

    [Fact]
    public void Help_ListsMaintenanceCommands()
    {
        var (_, output) = RunCli("--help");

        output.Should().Contain("self-update").And.Contain("uninstall");
    }

    // Sandboxes every uninstall target (data, cache, config roots) into a temp tree,
    // so the test can safely exercise real deletion without touching the machine.
    private static (Dictionary<string, string> Env, string DataDir, string CacheDir, string Root) UninstallSandbox()
    {
        string root = Directory.CreateTempSubdirectory().FullName;
        string dataDir  = Path.Combine(root, "data");
        string cacheDir = Path.Combine(root, "cache");
        Directory.CreateDirectory(dataDir);
        Directory.CreateDirectory(cacheDir);
        File.WriteAllText(Path.Combine(dataDir, "marker.bin"), "x");
        var env = new Dictionary<string, string>
        {
            ["ROVER_DATA_DIR"]   = dataDir,
            ["ROVER_CACHE_DIR"]  = cacheDir,
            // Both config locations resolve under ApplicationData; redirect it per-OS.
            ["APPDATA"]          = Path.Combine(root, "appdata"),
            ["XDG_CONFIG_HOME"]  = Path.Combine(root, "xdg"),
        };
        return (env, dataDir, cacheDir, root);
    }

    [Fact]
    public void Uninstall_Declined_DeletesNothing()
    {
        var (env, dataDir, cacheDir, root) = UninstallSandbox();
        try
        {
            var (exit, output) = RunCliWithEnv(env, "n\n", "uninstall");

            exit.Should().Be(1);
            output.Should().Contain("Cancelled");
            Directory.Exists(dataDir).Should().BeTrue("declining must not delete anything");
            Directory.Exists(cacheDir).Should().BeTrue();
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void Uninstall_WithYesFlag_DeletesDataAndCache()
    {
        var (env, dataDir, cacheDir, root) = UninstallSandbox();
        try
        {
            var (exit, output) = RunCliWithEnv(env, "", "uninstall", "--yes");

            exit.Should().Be(0);
            output.Should().Contain("Removed");
            Directory.Exists(dataDir).Should().BeFalse();
            Directory.Exists(cacheDir).Should().BeFalse();
            output.Should().Contain("binary", "the command explains how to remove the binary itself");
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void UnknownMode_ExitsOneWithError()
    {
        var (exit, output) = RunCli("bogus-mode");

        exit.Should().Be(1);
        output.Should().Contain("Unknown mode");
    }

    [Fact]
    public void SingleIp_MissingArgument_ExitsOneWithError()
    {
        var (exit, output) = RunCli("-a");

        exit.Should().Be(1);
        output.Should().Contain("IP address");
    }

    // A global flag before the mode must still route to that mode.
    // Covers the former "Unknown mode: --whois" failure for `rover --whois -a 8.8.8.8`.
    [Fact]
    public void FlagBeforeMode_RoutesToMode_NotUnknownMode()
    {
        var (exit, output) = RunCli("--whois", "-a");

        exit.Should().Be(1);
        output.Should().Contain("IP address", "the -a mode is recognised even though --whois precedes it");
        output.Should().NotContain("Unknown mode");
    }

    [Fact]
    public void Recommend_InvalidPreset_ExitsOneWithError()
    {
        var (exit, output) = RunCli("-r", "--preset", "nope");

        exit.Should().Be(1);
        output.Should().Contain("preset");
    }

    [Fact]
    public void Recommend_InvalidMaxPing_ExitsOneWithError()
    {
        var (exit, output) = RunCli("-r", "--max-ping", "abc");

        exit.Should().Be(1);
        output.Should().Contain("max-ping");
    }
}
