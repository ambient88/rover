namespace SubnetSearch.Core.Models.Data;

public class DownloadProgress
{
    /// <summary>Количество загруженных байт на данный момент.</summary>
    public long BytesDownloaded { get; init; }
    
    /// <summary>Общий размер файла в байтах (если известен).</summary>
    public long? TotalBytes { get; init; }
}