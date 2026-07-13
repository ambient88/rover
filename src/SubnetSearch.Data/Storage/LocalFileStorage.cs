using SubnetSearch.Core.Interfaces.Data;
using SubnetSearch.Core.Utilities;
using System.Collections.Concurrent;

namespace SubnetSearch.Data;

public class LocalFileStorage : IFileStorage
{
    private readonly string _dataDir;
    private readonly IReadOnlyDictionary<string, IFileIntegrityChecker> _integrityCheckers;
    private readonly string _fallbackSnapshotDir;
    private readonly ConcurrentDictionary<string, object> _validationLocks = new(
        StringComparer.OrdinalIgnoreCase);

    private sealed record IntegritySnapshot(long Length, long LastWriteTimeUtcTicks, string CheckerVersion);

    public LocalFileStorage(
        string dataDir,
        IReadOnlyDictionary<string, IFileIntegrityChecker>? integrityCheckers = null)
    {
        _dataDir = Path.GetFullPath(dataDir ?? throw new ArgumentNullException(nameof(dataDir)));
        _integrityCheckers = integrityCheckers ?? new Dictionary<string, IFileIntegrityChecker>();
        _fallbackSnapshotDir = DerivedCachePath.ForDataDirectory(_dataDir, "integrity");
        Directory.CreateDirectory(_dataDir);
    }

    private string SafePath(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
            throw new ArgumentException("File name must not be null or whitespace.", nameof(fileName));
        var fullPath = Path.GetFullPath(Path.Combine(_dataDir, fileName));
        if (!fullPath.StartsWith(_dataDir + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new ArgumentException($"Invalid file name: '{fileName}'", nameof(fileName));
        return fullPath;
    }

    public bool IsFileValid(string fileName, long minSize)
    {
        string filePath = SafePath(fileName);
        if (!File.Exists(filePath))
            return false;

        var fileInfo = new FileInfo(filePath);
        if (minSize > 0 && fileInfo.Length < minSize)
            return false;

        var checker = _integrityCheckers
            .FirstOrDefault(kvp => fileName.EndsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
            .Value;

        if (checker == null)
            return true;

        lock (_validationLocks.GetOrAdd(filePath, static _ => new object()))
        {
            fileInfo.Refresh();
            string snapshotPath = filePath + ".integrity.json";
            string fallbackSnapshotPath = FallbackSnapshotPath(filePath);
            string checkerVersion = GetCheckerVersion(checker);
            if (SnapshotMatches(snapshotPath, fileInfo, checkerVersion)
                || SnapshotMatches(fallbackSnapshotPath, fileInfo, checkerVersion))
            {
                return true;
            }
            if (LegacySnapshotMatches(snapshotPath, fileInfo, checker)
                || LegacySnapshotMatches(fallbackSnapshotPath, fileInfo, checker))
            {
                WriteValidatedSnapshot(
                    snapshotPath, fallbackSnapshotPath, fileInfo, checkerVersion);
                return true;
            }

            long lengthBeforeCheck = fileInfo.Length;
            long writeTimeBeforeCheck = fileInfo.LastWriteTimeUtc.Ticks;
            bool valid = checker.IsValid(filePath);
            fileInfo.Refresh();
            if (fileInfo.Length != lengthBeforeCheck
                || fileInfo.LastWriteTimeUtc.Ticks != writeTimeBeforeCheck)
            {
                return false;
            }

            if (valid)
                WriteValidatedSnapshot(
                    snapshotPath, fallbackSnapshotPath, fileInfo, checkerVersion);
            else
            {
                TryDelete(snapshotPath);
                TryDelete(fallbackSnapshotPath);
            }

            return valid;
        }
    }

    public async Task SaveAsync(string fileName, Stream content, CancellationToken cancellationToken = default)
    {
        string filePath = SafePath(fileName);
        string tempPath = filePath + ".tmp";
        string snapshotPath = filePath + ".integrity.json";
        string fallbackSnapshotPath = FallbackSnapshotPath(filePath);

        try
        {
            await using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
            {
                await content.CopyToAsync(fs, cancellationToken);
            }
            TryDelete(snapshotPath);
            TryDelete(fallbackSnapshotPath);
            File.Move(tempPath, filePath, overwrite: true);
        }
        catch
        {
            if (File.Exists(tempPath))
                File.Delete(tempPath);
            throw;
        }
    }

    private static string GetCheckerVersion(IFileIntegrityChecker checker)
        => $"{checker.GetType().FullName}:{checker.CacheVersion}";

    private static bool TryReadSnapshot(string path, out IntegritySnapshot snapshot)
    {
        snapshot = null!;
        try
        {
            if (!File.Exists(path))
                return false;
            snapshot = JsonSerializer.Deserialize<IntegritySnapshot>(File.ReadAllText(path))!;
            return snapshot != null;
        }
        catch
        {
            return false;
        }
    }

    private static bool SnapshotMatches(
        string path,
        FileInfo fileInfo,
        string checkerVersion)
        => TryReadSnapshot(path, out var snapshot)
           && snapshot.Length == fileInfo.Length
           && snapshot.LastWriteTimeUtcTicks == fileInfo.LastWriteTimeUtc.Ticks
           && snapshot.CheckerVersion == checkerVersion;

    private static bool LegacySnapshotMatches(
        string path,
        FileInfo fileInfo,
        IFileIntegrityChecker checker)
    {
        if (!TryReadSnapshot(path, out var snapshot)
            || snapshot.Length != fileInfo.Length
            || snapshot.LastWriteTimeUtcTicks != fileInfo.LastWriteTimeUtc.Ticks)
        {
            return false;
        }
        string prefix = checker.GetType().FullName + ":";
        if (!snapshot.CheckerVersion.StartsWith(prefix, StringComparison.Ordinal))
            return false;
        string suffix = snapshot.CheckerVersion[prefix.Length..];
        return suffix.Length == 32 && suffix.All(Uri.IsHexDigit);
    }

    private static void WriteValidatedSnapshot(
        string primaryPath,
        string fallbackPath,
        FileInfo fileInfo,
        string checkerVersion)
    {
        var snapshot = new IntegritySnapshot(
            fileInfo.Length, fileInfo.LastWriteTimeUtc.Ticks, checkerVersion);
        if (!WriteSnapshot(primaryPath, snapshot))
            WriteSnapshot(fallbackPath, snapshot);
    }

    private static bool WriteSnapshot(string path, IntegritySnapshot snapshot)
    {
        string tempPath = path + ".tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(tempPath, JsonSerializer.Serialize(snapshot));
            File.Move(tempPath, path, overwrite: true);
            return true;
        }
        catch
        {
            TryDelete(tempPath);
            return false;
        }
    }

    private string FallbackSnapshotPath(string filePath)
        => Path.Combine(_fallbackSnapshotDir, Path.GetFileName(filePath) + ".integrity.json");

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
        }
    }
}
