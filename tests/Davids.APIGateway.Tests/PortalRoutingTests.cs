using System.Net;
using System.Net.Http.Headers;
using Davids.APIGateway.Infrastructure.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Davids.APIGateway.Tests;

public sealed class PortalRoutingTests
{
    [Fact]
    [Trait("Category", "Integration")]
    public async Task BothPortalsRouteToTheirOwnUpstreamsAndEnforceRealmBoundaries()
    {
        static async Task<WebApplication> Start(string name)
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            var app = builder.Build();
            app.MapGet("/{**path}", (HttpContext ctx) => Results.Text($"{name}:{ctx.Request.Path}"));
            await app.StartAsync();
            return app;
        }
        static string Address(WebApplication app) => app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        await using var web = await Start("customer");
        await using var admin = await Start("admin");
        using var factory = GatewayTestSecurity.CreateGatewayFactory(Address(web), Address(admin), frontendWebDestination: Address(web));
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        foreach (var (path, expected) in new[] { ("/login", "customer:/login"), ("/login.js", "customer:/login.js"),
                                                  ("/admin/login", "admin:/login"), ("/admin/login.js", "admin:/login.js") })
        {
            using var response = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(expected, await response.Content.ReadAsStringAsync());
        }
        foreach (var (path, login) in new[] { ("/", "/login"), ("/admin", "/admin/login"), ("/admin/catalog", "/admin/login") })
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);
            request.Headers.Accept.ParseAdd("text/html");
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Equal(login, response.Headers.Location?.OriginalString);
        }
        var customerToken = GatewayTestSecurity.CreateCustomerToken(Guid.NewGuid());
        var adminToken = GatewayTestSecurity.CreateAdminToken(Guid.NewGuid());
        foreach (var (path, token, expected) in new[] { ("/", customerToken, "customer:/"), ("/app.js", customerToken, "customer:/app.js"),
            ("/admin", adminToken, "admin:/"), ("/admin/", adminToken, "admin:/"), ("/admin/catalog", adminToken, "admin:/catalog"), ("/admin/app.js", adminToken, "admin:/app.js") })
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(expected, await response.Content.ReadAsStringAsync());
        }
        foreach (var (path, token) in new[] { ("/admin/app.js", customerToken), ("/app.js", adminToken) })
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        using var api = await client.GetAsync("/admin-identity/me");
        Assert.Equal(HttpStatusCode.Unauthorized, api.StatusCode);
    }

    [Theory]
    [Trait("Category", "Unit")]
    [InlineData(null, "/admin")]
    [InlineData("https://example.com", "/admin")]
    [InlineData("//example.com", "/admin")]
    [InlineData("/", "/admin")]
    [InlineData("/admin/login", "/admin")]
    [InlineData("/admin/catalog", "/admin/catalog")]
    public void AdminReturnsStayOnPortal(string? input, string expected)
        => Assert.Equal(expected, GatewayBffEndpoints.NormalizeLocalReturnUrl(input));
}
