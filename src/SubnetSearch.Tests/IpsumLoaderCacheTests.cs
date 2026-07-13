using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

public class IpsumLoaderCacheTests
{
    private static string Temp(string content)
    {
        var p = Path.Combine(Path.GetTempPath(), $"ipsum-c-{Guid.NewGuid():N}.txt");
        File.WriteAllText(p, content);
        return p;
    }

    [Fact]
    public async Task Load_SecondCall_ReadsFromCache()
    {
        var path = Temp("1.2.3.4\t5\n8.8.8.8\t9\n");
        try
        {
            var loader = new IpsumLoader();
            (await loader.LoadAsync(path)).Should().HaveCount(2); // builds + writes cache
            (await loader.LoadAsync(path)).Should().HaveCount(2); // reads cache
        }
        finally { File.Delete(path); }
    }
}
