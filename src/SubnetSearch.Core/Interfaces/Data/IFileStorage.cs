namespace SubnetSearch.Core.Interfaces.Data;

/// <summary>
/// Abstraction over a local file store.
/// </summary>
public interface IFileStorage
{
    /// <summary>
    /// Checks whether the file exists and passes its integrity check.
    /// </summary>
    /// <param name="fileName">File name.</param>
    /// <param name="minSize">Minimum acceptable size in bytes.</param>
    /// <returns>true if the file exists and is valid.</returns>
    bool IsFileValid(string fileName, long minSize);

    /// <summary>
    /// Saves a stream to a file with an atomic replace (through a temp file).
    /// </summary>
    /// <param name="fileName">File name.</param>
    /// <param name="content">Data stream.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task SaveAsync(string fileName, Stream content, CancellationToken cancellationToken = default);
}