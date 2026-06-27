namespace SubnetSearch.Data;

public class ProgressStream : Stream
{
    private readonly Stream _baseStream;
    private readonly Action<long> _onRead;
    private long _totalRead;

    public ProgressStream(Stream baseStream, Action<long> onRead)
    {
        _baseStream = baseStream ?? throw new ArgumentNullException(nameof(baseStream));
        _onRead = onRead ?? throw new ArgumentNullException(nameof(onRead));
    }

    public override bool CanRead => _baseStream.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _baseStream.Length;
    public override long Position
    {
        get => _baseStream.Position;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int read = _baseStream.Read(buffer, offset, count);
        if (read > 0)
        {
            _totalRead += read;
            _onRead(_totalRead);
        }
        return read;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        int read = await _baseStream.ReadAsync(buffer, offset, count, cancellationToken);
        if (read > 0)
        {
            _totalRead += read;
            _onRead(_totalRead);
        }
        return read;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _baseStream.Dispose();
        base.Dispose(disposing);
    }

    public override void Flush() => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
}