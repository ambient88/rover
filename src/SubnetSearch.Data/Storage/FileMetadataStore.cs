using System.Text.Json;

namespace SubnetSearch.Data;

public class FileMetadataStore(string dataDir)
{
    private static readonly JsonSerializerOptions _json = new() { WriteIndented = false };

    private string MetaPath(string fileName) =>
        Path.Combine(dataDir, fileName + ".meta.json");

    public FileMetadata? Load(string fileName)
    {
        var path = MetaPath(fileName);
        if (!File.Exists(path)) return null;
        try
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<FileMetadata>(json);
        }
        catch { return null; }
    }

    public void Save(string fileName, FileMetadata meta)
    {
        var path    = MetaPath(fileName);
        var tmpPath = path + ".tmp";
        try
        {
            File.WriteAllText(tmpPath, JsonSerializer.Serialize(meta, _json));
            File.Move(tmpPath, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best-effort: metadata loss triggers a re-download on next run, not data corruption.
            try { File.Delete(tmpPath); } catch { }
        }
    }

    public bool IsStale(string fileName, TimeSpan maxAge)
    {
        var meta = Load(fileName);
        if (meta == null) return true;
        return DateTimeOffset.UtcNow - meta.LastChecked > maxAge;
    }
}
