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
