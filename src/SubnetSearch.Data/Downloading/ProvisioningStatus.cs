using SubnetSearch.Core.Interfaces.Data;
using SubnetSearch.Core.Models.Data;

namespace SubnetSearch.Data;

/// <summary>Data provisioning mode for the current run.</summary>
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

    /// <summary>Whether at least one valid local file exists (otherwise it is a first run).</summary>
    public bool AnyFileValid() => _files.Any(f => _storage.IsFileValid(f.FileName, f.MinSize));

    public bool AnyFileInvalid() => _files.Any(f => !_storage.IsFileValid(f.FileName, f.MinSize));

    /// <summary>Whether any files need downloading (missing/corrupt OR the TTL has expired).</summary>
    public bool AnyPending() => _files.Any(IsPending);

    private bool IsPending(FileDescriptor f)
    {
        if (!_storage.IsFileValid(f.FileName, f.MinSize)) return true; // missing or corrupt
        if (f.MaxAge is null) return false;                            // download-once
        return _meta.IsStale(f.FileName, f.MaxAge.Value);              // TTL expired
    }

    /// <summary>
    /// A pure mode-selection rule (no disk or network, tested in isolation):
    /// Explicit update or first install uses Visible mode.
    /// A partial installation uses Silent mode. Valid local data uses None.
    /// </summary>
    public static ProvisioningMode Decide(bool isUpdateCommand, bool anyFileValid, bool anyFileInvalid)
    {
        if (isUpdateCommand) return ProvisioningMode.Visible;
        if (!anyFileValid)   return ProvisioningMode.Visible; // first run
        if (anyFileInvalid)  return ProvisioningMode.Silent;
        return ProvisioningMode.None;
    }
}
