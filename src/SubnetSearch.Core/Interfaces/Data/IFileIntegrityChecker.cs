namespace SubnetSearch.Core.Interfaces.Data;

/// <summary>
/// Проверяет целостность локального файла.
/// </summary>
public interface IFileIntegrityChecker
{
    bool IsValid(string filePath);
}