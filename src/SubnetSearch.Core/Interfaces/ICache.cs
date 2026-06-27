namespace SubnetSearch.Core.Interfaces;

public interface ICache
{
    T? GetOrAdd<T>(string key, Func<T> factory, TimeSpan? ttl = null) where T : class?;
    void Remove(string key);
    void Clear();
}
