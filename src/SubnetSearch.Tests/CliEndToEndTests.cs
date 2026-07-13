using System.Diagnostics;
using FluentAssertions;

namespace SubnetSearch.Tests;

// End-to-end тесты CLI: запускаем реальный собранный бинарь rover подпроцессом и проверяем
// код возврата и вывод. Проверяются пути с немедленным выходом (без сети): version, help,
// валидация аргументов. CLI собирается через build-order ProjectReference (см. .csproj).
public class CliEndToEndTests
{
    // Ищет собранный rover (rover.exe на Windows, иначе rover.dll) в bin CLI-проекта.
    private static string LocateCliBinDir()
    {
        // База тестов: ...\src\SubnetSearch.Tests\bin\<Config>\net8.0\
        var baseDir = AppContext.BaseDirectory;
        var cliDir = baseDir.Replace(
            $"{Path.DirectorySeparatorChar}SubnetSearch.Tests{Path.DirectorySeparatorChar}",
            $"{Path.DirectorySeparatorChar}SubnetSearch.Cli{Path.DirectorySeparatorChar}");
        if (Directory.Exists(cliDir) &&
            (File.Exists(Path.Combine(cliDir, "rover.dll")) || File.Exists(Path.Combine(cliDir, "rover.exe"))))
            return cliDir;

        // Фолбэк: ищем самый свежий rover.dll под bin CLI-проекта.
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
        output.Should().Contain("SubnetSearch").And.Contain("0.0.1");
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
    public void UnknownMode_ExitsOneWithError() // краевой случай: неизвестный режим
    {
        var (exit, output) = RunCli("bogus-mode");

        exit.Should().Be(1);
        output.Should().Contain("Unknown mode");
    }

    [Fact]
    public void SingleIp_MissingArgument_ExitsOneWithError() // краевой случай: -a без IP
    {
        var (exit, output) = RunCli("-a");

        exit.Should().Be(1);
        output.Should().Contain("IP address");
    }

    // F17: a global flag before the mode must still route to that mode, not fail as "Unknown mode".
    // Regression for `rover --whois -a 8.8.8.8` → "Unknown mode: --whois".
    [Fact]
    public void FlagBeforeMode_RoutesToMode_NotUnknownMode()
    {
        var (exit, output) = RunCli("--whois", "-a");

        exit.Should().Be(1);
        output.Should().Contain("IP address", "the -a mode is recognised even though --whois precedes it");
        output.Should().NotContain("Unknown mode");
    }

    [Fact]
    public void Recommend_InvalidPreset_ExitsOneWithError() // краевой случай: невалидный пресет
    {
        var (exit, output) = RunCli("-r", "--preset", "nope");

        exit.Should().Be(1);
        output.Should().Contain("preset");
    }

    [Fact]
    public void Recommend_InvalidMaxPing_ExitsOneWithError() // краевой случай: нечисловой --max-ping
    {
        var (exit, output) = RunCli("-r", "--max-ping", "abc");

        exit.Should().Be(1);
        output.Should().Contain("max-ping");
    }
}
