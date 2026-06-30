namespace SubnetSearch.Core.Models.Data;

public class DownloadOptions
{
    /// <summary>Максимальное количество повторных попыток при ошибке.</summary>
    public int MaxRetries { get; init; } = 3;

    /// <summary>Базовая задержка между повторами (мс), умножается на номер попытки.</summary>
    public int RetryDelayMilliseconds { get; init; } = 2000;

    /// <summary>Таймаут для каждой HTTP‑попытки (сек).</summary>
    public int TimeoutSeconds { get; init; } = 600;

    /// <summary>
    /// Каталог для хранения частично скачанных файлов (.part) между запусками.
    /// Если null — используется системный temp (resume не переживает перезапуск).
    /// </summary>
    public string? PartialDownloadsDir { get; init; }

    /// <summary>Пытаться ли докачать частично загруженный файл (Range‑запрос).</summary>
    public bool UseResume { get; init; } = true;

    /// <summary>Прокси‑сервер (строка вида http://host:port).</summary>
    public string? Proxy { get; init; }

    /// <summary>Ожидаемая SHA256‑строка (hex) для проверки после загрузки.</summary>
    public string? ChecksumSha256 { get; init; }

    // Можно добавить MD5, но оставим пока SHA256
}