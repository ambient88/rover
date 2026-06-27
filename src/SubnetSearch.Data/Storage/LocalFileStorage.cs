using SubnetSearch.Core.Interfaces.Data;

namespace SubnetSearch.Data;

public class LocalFileStorage : IFileStorage
{
    private readonly string _dataDir;
    private readonly IReadOnlyDictionary<string, IFileIntegrityChecker> _integrityCheckers;

    public LocalFileStorage(
        string dataDir,
        IReadOnlyDictionary<string, IFileIntegrityChecker>? integrityCheckers = null)
    {
        _dataDir = Path.GetFullPath(dataDir ?? throw new ArgumentNullException(nameof(dataDir)));
        _integrityCheckers = integrityCheckers ?? new Dictionary<string, IFileIntegrityChecker>();
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

        return checker?.IsValid(filePath) ?? true;
    }

    public async Task SaveAsync(string fileName, Stream content, CancellationToken cancellationToken = default)
    {
        string filePath = SafePath(fileName);
        string tempPath = filePath + ".tmp";

        try
        {
            await using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
            {
                await content.CopyToAsync(fs, cancellationToken);
            }
            File.Move(tempPath, filePath, overwrite: true);
        }
        catch
        {
            if (File.Exists(tempPath))
                File.Delete(tempPath);
            throw;
        }
    }
}