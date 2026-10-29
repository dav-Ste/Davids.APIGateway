using Davids.APIGateway.Infrastructure;
using Xunit;

namespace Davids.APIGateway.Tests;

[Trait("Category", "Unit")]
public sealed class ArchitectureTests
{
    [Fact]
    public void GatewayInfrastructureDoesNotDependOnApiHostOrDownstreamServiceAssemblies()
    {
        var infraAssembly = typeof(GatewaySecurityExtensions).Assembly;
        var referencedNames = infraAssembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain("Davids.APIGateway.Api", referencedNames, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain(referencedNames, n => n.StartsWith("Davids.Services.", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(referencedNames, n => n.StartsWith("Davids.Frontend", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(referencedNames, n => n.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(referencedNames, n => n.StartsWith("OpenIddict.Server", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void GatewayApiDependsOnlyOnGatewayInfrastructureAndServiceDefaultsWithinWorkspace()
    {
        var apiAssembly = typeof(Program).Assembly;
        var davidsRefs = apiAssembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .Where(n => n.StartsWith("Davids.", StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(["Davids.APIGateway.Infrastructure", "Davids.ServiceDefaults"], davidsRefs);
    }
}
