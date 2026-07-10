using SubnetSearch.Core.Interfaces.Data;
using SubnetSearch.Core.Models.Data;

namespace SubnetSearch.Data;

/// <summary>Режим провижининга данных на текущем запуске.</summary>
public enum ProvisioningMode
{
    None,     // всё свежее — ничего не делаем, ноль вывода
    Silent,   // есть устаревшее/недостающее — тихий рефреш (одна строка), без таблицы
    Visible   // установка / rover update / первый запуск — полный визуал прогресса
}

/// <summary>
/// Читает состояние локальных data-файлов (без сети) и решает, в каком режиме
/// провижинить: определяет наличие валидных файлов и «есть ли что обновлять» (missing/stale),
/// а также применяет чистое правило выбора режима (<see cref="Decide"/>).
/// Логика «нужна ли загрузка файла» зеркалит решение DownloadManager (missing/corrupt
/// ИЛИ TTL истёк), чтобы Silent-путь не расходился с фактической загрузкой.
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
    /// команда update ИЛИ первый запуск (нет валидных файлов) → Visible;
    /// иначе есть что обновлять → Silent; иначе → None.
    /// </summary>
    public static ProvisioningMode Decide(bool isUpdateCommand, bool anyFileValid, bool anyPending)
    {
        if (isUpdateCommand) return ProvisioningMode.Visible;
        if (!anyFileValid)   return ProvisioningMode.Visible; // первый запуск
        if (anyPending)      return ProvisioningMode.Silent;
        return ProvisioningMode.None;
    }
}
