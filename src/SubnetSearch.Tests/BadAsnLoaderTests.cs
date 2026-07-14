using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

public class BadAsnLoaderTests
{
    [Fact]
    public async Task LoadAsync_ParsesWhitespaceSeparatedAsns()
    {
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "174 612\nAS1442\tinvalid");

            var result = await new BadAsnLoader().LoadAsync(path);

            result.Should().BeEquivalentTo([174u, 612u, 1442u]);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task LoadAsync_MissingFile_ReturnsEmptySet()
    {
        string path = Path.Combine(Path.GetTempPath(), $"nope-{Guid.NewGuid():N}.txt");

        var result = await new BadAsnLoader().LoadAsync(path);

        result.Should().BeEmpty();
    }

    [Fact]
    public void DefaultManifest_ContainsBadAsnSource()
        => DownloadManagerFactory.GetDefaultFiles()
            .Should().Contain(file => file.FileName == "bad-asn-list.txt");
}
