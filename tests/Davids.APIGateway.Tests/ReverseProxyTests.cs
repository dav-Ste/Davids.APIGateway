using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Davids.APIGateway.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Davids.APIGateway.Tests;

public sealed class ReverseProxyTests
{
    [Theory]
    [InlineData("GET", "/identity/me", "/me", "identity", "", "user")]
    [InlineData("GET", "/admin-identity/me", "/me", "admin-identity", "", "admin")]
    [InlineData("GET", "/admin-identity/users", "/users", "admin-identity", "", "admin")]
    [InlineData("POST", "/customers", "/customers", "customers", "", "user")]
    [InlineData("GET", "/customers", "/customers", "customers", "", "admin")]
    [InlineData("GET", "/customers", "/customers", "customers", "?search=jane&state=valid&vip=true", "admin")]
    [InlineData("PUT", "/customers/01234567-89ab-cdef-0123-456789abcdef", "/customers/01234567-89ab-cdef-0123-456789abcdef", "customers", "", "admin")]
    public async Task AuthenticatedServicePathQueryAndVerifiedIdentityHeadersAreForwardedToDirectBackendClusters(
        string method,
        string gatewayPath,
        string expectedDownstreamPath,
        string expectedCluster,
        string query,
        string role)
    {
        static async Task<WebApplication> StartFakeClusterAsync(string clusterName)
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            var app = builder.Build();
            app.MapMethods("/{**path}", new[] { "GET", "POST", "PUT", "PATCH", "DELETE" }, (HttpContext context) =>
                Results.Json(new
                {
                    cluster = clusterName,
                    path = context.Request.Path.Value,
                    query = context.Request.QueryString.Value ?? string.Empty,
                    method = context.Request.Method,
                    authorization = context.Request.Headers.Authorization.ToString(),
                    verifiedUserId = context.Request.Headers[ReverseProxyExtensions.VerifiedUserIdHeader].ToString(),
                    verifiedRole = context.Request.Headers[ReverseProxyExtensions.VerifiedUserRoleHeader].ToString(),
                    verifiedTokenId = context.Request.Headers[ReverseProxyExtensions.VerifiedTokenIdHeader].ToString(),
                    verifiedScheme = context.Request.Headers[ReverseProxyExtensions.VerifiedSchemeHeader].ToString(),
                    correlationId = context.Request.Headers["X-Correlation-ID"].ToString(),
                    traceparent = context.Request.Headers["traceparent"].ToString()
                }));
            await app.StartAsync();
            return app;
        }

        static string GetAddress(WebApplication app) =>
            app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();

        await using var identityCluster = await StartFakeClusterAsync("identity");
        await using var adminIdentityCluster = await StartFakeClusterAsync("admin-identity");
        await using var customersCluster = await StartFakeClusterAsync("customers");

        try
        {
            using var factory = GatewayTestSecurity.CreateGatewayFactory(
                backendDestination: GetAddress(customersCluster),
                identityDestination: GetAddress(identityCluster),
                adminIdentityDestination: GetAddress(adminIdentityCluster),
                customersDestination: GetAddress(customersCluster));

            var subjectId = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef");
            var tokenId = "token-id-9876543210";
            var token = GatewayTestSecurity.CreateTokenForRole(subjectId, role, tokenId);

            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            client.DefaultRequestHeaders.Add(ReverseProxyExtensions.VerifiedUserIdHeader, "spoofed-id");
            client.DefaultRequestHeaders.Add(ReverseProxyExtensions.VerifiedUserRoleHeader, "admin");
            client.DefaultRequestHeaders.Add(ReverseProxyExtensions.VerifiedTokenIdHeader, "spoofed-jti");
            client.DefaultRequestHeaders.Add("X-Correlation-ID", "api-call-42");

            using var request = new HttpRequestMessage(new HttpMethod(method), gatewayPath + query);
            if (method is "POST" or "PUT")
            {
                request.Content = JsonContent.Create(new
                {
                    customerId = subjectId,
                    fullName = "Jane Doe",
                    address = "1 Main Street",
                    email = "jane@example.com",
                    state = "valid"
                });
            }

            using var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();

            using var payload = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
            var root = payload.RootElement;
            Assert.Equal(expectedCluster, root.GetProperty("cluster").GetString());
            Assert.Equal(expectedDownstreamPath, root.GetProperty("path").GetString());
            Assert.Equal(query, root.GetProperty("query").GetString());
            Assert.Equal(method, root.GetProperty("method").GetString());
            Assert.Equal($"Bearer {token}", root.GetProperty("authorization").GetString());
            Assert.Equal(subjectId.ToString("N"), root.GetProperty("verifiedUserId").GetString());
            Assert.Equal(role, root.GetProperty("verifiedRole").GetString());
            Assert.Equal(tokenId, root.GetProperty("verifiedTokenId").GetString());
            Assert.Equal(role == "admin" ? "AdminBearer" : "CustomerBearer", root.GetProperty("verifiedScheme").GetString());
            Assert.Equal("api-call-42", root.GetProperty("correlationId").GetString());
            Assert.StartsWith("00-", root.GetProperty("traceparent").GetString());
            Assert.Equal("api-call-42", response.Headers.GetValues("X-Correlation-ID").Single());
        }
        finally
        {
            await identityCluster.StopAsync();
            await adminIdentityCluster.StopAsync();
            await customersCluster.StopAsync();
        }
    }

    [Fact]
    public async Task GatewayOverwritesSpoofedXForwardedForAndIsolatesEdgeRateLimitsPerClientIp()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var fakeIdentity = builder.Build();
        fakeIdentity.MapPost("/sign-up", (HttpContext ctx) => Results.Json(new
        {
            forwardedFor = ctx.Request.Headers["X-Forwarded-For"].ToString()
        }));
        await fakeIdentity.StartAsync();

        try
        {
            var identityAddress = fakeIdentity.Services
                .GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!
                .Addresses.Single();

            using var baseFactory = GatewayTestSecurity.CreateGatewayFactory(
                backendDestination: identityAddress,
                identityDestination: identityAddress,
                adminIdentityDestination: identityAddress,
                customersDestination: identityAddress);
            using var factory = baseFactory.WithWebHostBuilder(wb =>
            {
                wb.UseSetting("RateLimiting:AdminAuthPermitLimit", "2");
                wb.UseSetting("RateLimiting:CustomerAuthPermitLimit", "2");
            });
            using var _ = factory.CreateClient();

            // 1. Client 198.51.100.10 tries to spoof X-Forwarded-For: 10.0.0.99 on /identity/sign-up;
            //    YARP overwrites X-Forwarded-For with verified client IP 198.51.100.10.
            var signUpCtx = await factory.Server.SendAsync(ctx =>
            {
                ctx.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.10");
                ctx.Request.Method = "POST";
                ctx.Request.Path = "/identity/sign-up";
                ctx.Request.Headers["X-Forwarded-For"] = "10.0.0.99";
                ctx.Request.ContentType = "application/json";
            });
            Assert.Equal(StatusCodes.Status200OK, signUpCtx.Response.StatusCode);
            using var doc = await JsonDocument.ParseAsync(signUpCtx.Response.Body);
            Assert.Equal("198.51.100.10", doc.RootElement.GetProperty("forwardedFor").GetString());

            // 2. Exhaust gateway-admin-auth (limit=2) for attacker IP 198.51.100.50 on /auth/login.
            static Task<HttpContext> SendLoginAsync(Microsoft.AspNetCore.TestHost.TestServer server, string ip) =>
                server.SendAsync(ctx =>
                {
                    ctx.Connection.RemoteIpAddress = IPAddress.Parse(ip);
                    ctx.Request.Method = "GET";
                    ctx.Request.Path = "/auth/login";
                    ctx.Request.QueryString = new QueryString("?returnUrl=%2F");
                });

            Assert.Equal(StatusCodes.Status302Found, (await SendLoginAsync(factory.Server, "198.51.100.50")).Response.StatusCode);
            Assert.Equal(StatusCodes.Status302Found, (await SendLoginAsync(factory.Server, "198.51.100.50")).Response.StatusCode);

            var rejected = await SendLoginAsync(factory.Server, "198.51.100.50");
            Assert.Equal(StatusCodes.Status429TooManyRequests, rejected.Response.StatusCode);
            Assert.False(string.IsNullOrWhiteSpace(rejected.Response.Headers.RetryAfter.ToString()));

            // 3. Legitimate administrator on 198.51.100.60 is completely unaffected.
            Assert.Equal(StatusCodes.Status302Found, (await SendLoginAsync(factory.Server, "198.51.100.60")).Response.StatusCode);
        }
        finally
        {
            await fakeIdentity.StopAsync();
        }
    }

    [Fact]
    public async Task EdgeHttpMethodAllowlistAndPublicSignUpMethodRoutingEnforceStagingDastInvariants()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var fakeIdentity = builder.Build();
        fakeIdentity.MapPost("/sign-up", () => Results.StatusCode(StatusCodes.Status201Created));
        await fakeIdentity.StartAsync();

        try
        {
            var identityAddress = fakeIdentity.Services
                .GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!
                .Addresses.Single();

            using var factory = GatewayTestSecurity.CreateGatewayFactory(
                backendDestination: identityAddress,
                identityDestination: identityAddress,
                adminIdentityDestination: identityAddress,
                customersDestination: identityAddress);
            using var client = factory.CreateClient();

            // Non-standard / cross-site tracing HTTP methods are rejected with 405 + explicit Allow header at the edge.
            foreach (var method in new[] { "TRACE", "QUERY", "PROPFIND" })
            {
                using var req = new HttpRequestMessage(new HttpMethod(method), "/gateway-info");
                using var resp = await client.SendAsync(req);
                Assert.Equal(HttpStatusCode.MethodNotAllowed, resp.StatusCode);
                Assert.Contains(HttpMethod.Get, resp.Content.Headers.Allow.Select(m => new HttpMethod(m)));
                Assert.Equal("nosniff", resp.Headers.GetValues("X-Content-Type-Options").Single());
            }

            // GET /identity/sign-up routes anonymously to Identity.Api and returns 405 Method Not Allowed (not 401 fallthrough).
            using var getSignUp = await client.GetAsync("/identity/sign-up");
            Assert.Equal(HttpStatusCode.MethodNotAllowed, getSignUp.StatusCode);
        }
        finally
        {
            await fakeIdentity.StopAsync();
        }
    }
}
