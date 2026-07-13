using SubnetSearch.Core.Interfaces.Data;
using SubnetSearch.Core.Models.Data;

namespace SubnetSearch.Data;

/// <summary>Режим провижининга данных на текущем запуске.</summary>
public enum ProvisioningMode
{
    None,     // Valid local data starts immediately.
    Silent,   // Missing or invalid files are restored quietly.
    Visible   // Installation and explicit update show full progress.
}

/// <summary>
/// Reads local data status and selects the startup provisioning mode.
/// Interactive commands use valid local data without waiting for a TTL refresh.
/// </summary>
public sealed class ProvisioningStatus
{
    private readonly IFileStorage _storage;
    private readonly IReadOnlyList<FileDescriptor> _files;
    private readonly FileMetadataStore _meta;

    public ProvisioningStatus(IFileStorage storage, IReadOnlyList<FileDescriptor> files, FileMetadataStore meta)
    {
        _storage = storage;
        _files   = files;
        _meta    = meta;
    }

    /// <summary>Есть ли хотя бы один валидный локальный файл (иначе — первый запуск).</summary>
    public bool AnyFileValid() => _files.Any(f => _storage.IsFileValid(f.FileName, f.MinSize));

    public bool AnyFileInvalid() => _files.Any(f => !_storage.IsFileValid(f.FileName, f.MinSize));

    /// <summary>Есть ли файлы, которые нужно скачать (отсутствуют/битые ИЛИ TTL истёк).</summary>
    public bool AnyPending() => _files.Any(IsPending);

    private bool IsPending(FileDescriptor f)
    {
        if (!_storage.IsFileValid(f.FileName, f.MinSize)) return true; // отсутствует/битый
        if (f.MaxAge is null) return false;                            // download-once
        return _meta.IsStale(f.FileName, f.MaxAge.Value);              // TTL истёк
    }

    /// <summary>
    /// Чистое правило выбора режима (без диска/сети — тестируется изолированно):
    /// Explicit update or first install uses Visible mode.
    /// A partial installation uses Silent mode. Valid local data uses None.
    /// </summary>
    public static ProvisioningMode Decide(bool isUpdateCommand, bool anyFileValid, bool anyFileInvalid)
    {
        if (isUpdateCommand) return ProvisioningMode.Visible;
        if (!anyFileValid)   return ProvisioningMode.Visible; // первый запуск
        if (anyFileInvalid)  return ProvisioningMode.Silent;
        return ProvisioningMode.None;
    }
}
