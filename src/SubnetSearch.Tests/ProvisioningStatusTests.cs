using FluentAssertions;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

public class ProvisioningStatusTests
{
    [Theory]
    // isUpdate, anyFileValid, anyPending → ожидаемый режим
    [InlineData(true,  true,  true,  ProvisioningMode.Visible)]  // update всегда Visible
    [InlineData(true,  true,  false, ProvisioningMode.Visible)]  // update даже когда всё свежее
    [InlineData(true,  false, true,  ProvisioningMode.Visible)]
    [InlineData(false, false, true,  ProvisioningMode.Visible)]  // первый запуск — нет валидных файлов
    [InlineData(false, false, false, ProvisioningMode.Visible)]  // нет валидных → Visible
    [InlineData(false, true,  true,  ProvisioningMode.Silent)]   // есть данные + что-то устарело
    [InlineData(false, true,  false, ProvisioningMode.None)]     // всё свежее — тишина
    public void Decide_SelectsMode(bool isUpdate, bool anyFileValid, bool anyPending, ProvisioningMode expected)
        => ProvisioningStatus.Decide(isUpdate, anyFileValid, anyPending).Should().Be(expected);
}
