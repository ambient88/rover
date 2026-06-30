namespace SubnetSearch.Core.Interfaces.Data;

/// <summary>
/// Абстракция для работы с локальным файловым хранилищем.
/// </summary>
public interface IFileStorage
{
    /// <summary>
    /// Проверяет, существует ли файл и проходит ли он проверку целостности.
    /// </summary>
    /// <param name="fileName">Имя файла.</param>
    /// <param name="minSize">Минимально допустимый размер в байтах.</param>
    /// <returns>true, если файл существует и корректен.</returns>
    bool IsFileValid(string fileName, long minSize);

    /// <summary>
    /// Сохраняет поток в файл с атомарной заменой (через временный файл).
    /// </summary>
    /// <param name="fileName">Имя файла.</param>
    /// <param name="content">Поток с данными.</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    Task SaveAsync(string fileName, Stream content, CancellationToken cancellationToken = default);
}