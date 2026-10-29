using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Davids.APIGateway.Infrastructure;
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

public sealed class FrontendProxyTests
{
    [Fact]
    public async Task AdminFrontendBlocksAnonymousAndCustomerUsersWhileAllowingPublicLoginAssets()
    {
        var frontendHits = 0;
        var downstreamBuilder = WebApplication.CreateBuilder();
        downstreamBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var downstream = downstreamBuilder.Build();
        downstream.MapGet("/{**path}", (HttpContext context) =>
        {
            Interlocked.Increment(ref frontendHits);
            return Results.Text($"served:{context.Request.Path.Value}");
        });
        await downstream.StartAsync();

        try
        {
            var server = downstream.Services.GetRequiredService<IServer>();
            var destination = server.Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            using var factory = GatewayTestSecurity.CreateGatewayFactory(destination, destination);
            using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });

            // Browser HTML GET to / without admin session redirects to /login without hitting downstream.
            using var anonHtml = new HttpRequestMessage(HttpMethod.Get, "/");
            anonHtml.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
            using var redirectResponse = await client.SendAsync(anonHtml);
            Assert.Equal(HttpStatusCode.Found, redirectResponse.StatusCode);
            Assert.Equal("/login", redirectResponse.Headers.Location?.OriginalString);
            Assert.Contains("no-store", redirectResponse.Headers.CacheControl?.ToString() ?? string.Empty);

            // Non-HTML request to admin JS/CSS asset without admin session returns 401.
            using var anonAsset = await client.GetAsync("/app.js");
            Assert.Equal(HttpStatusCode.Unauthorized, anonAsset.StatusCode);

            // Authenticated customer ('user' from Davids.Services.Identity) receives 403 Forbidden on / and /app.js.
            var customerToken = GatewayTestSecurity.CreateCustomerToken(Guid.NewGuid(), "user");
            using var customerHtml = new HttpRequestMessage(HttpMethod.Get, "/");
            customerHtml.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
            customerHtml.Headers.Authorization = new AuthenticationHeaderValue("Bearer", customerToken);
            using var customerForbidden = await client.SendAsync(customerHtml);
            Assert.Equal(HttpStatusCode.Forbidden, customerForbidden.StatusCode);

            using var customerAsset = new HttpRequestMessage(HttpMethod.Get, "/app.js");
            customerAsset.Headers.Authorization = new AuthenticationHeaderValue("Bearer", customerToken);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(customerAsset)).StatusCode);

            // Forged customer-key token claiming 'admin' is rejected with 401 Unauthorized.
            var forgedAdmin = GatewayTestSecurity.CreateCustomerToken(Guid.NewGuid(), "admin");
            using var forgedReq = new HttpRequestMessage(HttpMethod.Get, "/app.js");
            forgedReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", forgedAdmin);
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(forgedReq)).StatusCode);

            Assert.Equal(0, frontendHits);

            // Minimal public /login surface is reachable anonymously so administrators can initiate OIDC SSO.
            foreach (var publicLoginAsset in new[] { "/login", "/login.css", "/login.js", "/favicon.svg" })
            {
                using var loginRes = await client.GetAsync(publicLoginAsset);
                Assert.Equal(HttpStatusCode.OK, loginRes.StatusCode);
                Assert.Equal($"served:{publicLoginAsset}", await loginRes.Content.ReadAsStringAsync());
            }

            Assert.Equal(4, frontendHits);
        }
        finally
        {
            await downstream.StopAsync();
        }
    }

    [Fact]
    public async Task GatewayProxiesAdminFrontendForVerifiedAdminAndStripsCredentialsAndPropagatesW3CTraceContext()
    {
        var downstreamBuilder = WebApplication.CreateBuilder();
        downstreamBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var downstream = downstreamBuilder.Build();
        downstream.MapGet("/{**path}", (HttpContext context) => Results.Json(new
        {
            path = context.Request.Path.Value,
            authorization = context.Request.Headers.Authorization.ToString(),
            cookie = context.Request.Headers.Cookie.ToString(),
            spoofedUserId = context.Request.Headers[ReverseProxyExtensions.VerifiedUserIdHeader].ToString(),
            correlationId = context.Request.Headers["X-Correlation-ID"].ToString(),
            traceparent = context.Request.Headers["traceparent"].ToString(),
            tracestate = context.Request.Headers["tracestate"].ToString(),
            baggage = context.Request.Headers["baggage"].ToString()
        }));
        await downstream.StartAsync();

        try
        {
            var server = downstream.Services.GetRequiredService<IServer>();
            var destination = server.Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            using var factory = GatewayTestSecurity.CreateGatewayFactory(destination, destination);

            var adminToken = GatewayTestSecurity.CreateAdminToken(Guid.NewGuid(), "admin");
            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
            client.DefaultRequestHeaders.Add("Cookie", $"{GatewayAuthPolicies.AdminBffCookieName}=untrusted-cookie-value");
            client.DefaultRequestHeaders.Add(ReverseProxyExtensions.VerifiedUserIdHeader, "spoofed-user");
            client.DefaultRequestHeaders.Add("X-Correlation-ID", "admin-web:request-123");
            client.DefaultRequestHeaders.Add("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
            client.DefaultRequestHeaders.Add("tracestate", "vendor=value");
            client.DefaultRequestHeaders.Add("baggage", "tenant=demo,user=admin");

            using var response = await client.GetAsync("/");
            response.EnsureSuccessStatusCode();
            Assert.Equal("admin-web:request-123", response.Headers.GetValues("X-Correlation-ID").Single());
            Assert.Equal("4bf92f3577b34da6a3ce929d0e0e4736", response.Headers.GetValues("X-Trace-Id").Single());
            Assert.Contains("script-src 'self'", response.Headers.GetValues("Content-Security-Policy").Single());
            Assert.Contains("no-store", response.Headers.CacheControl?.ToString() ?? string.Empty);

            using var payload = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
            var forwarded = payload.RootElement;
            Assert.Equal("/", forwarded.GetProperty("path").GetString());
            Assert.Equal(string.Empty, forwarded.GetProperty("authorization").GetString());
            Assert.Equal(string.Empty, forwarded.GetProperty("cookie").GetString());
            Assert.Equal(string.Empty, forwarded.GetProperty("spoofedUserId").GetString());
            Assert.Equal("admin-web:request-123", forwarded.GetProperty("correlationId").GetString());
            Assert.Equal("vendor=value", forwarded.GetProperty("tracestate").GetString());
            var baggageItems = forwarded.GetProperty("baggage").GetString()!
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(item => item.Replace(" ", string.Empty, StringComparison.Ordinal));
            Assert.Equal(new[] { "tenant=demo", "user=admin" }, baggageItems);

            var traceparent = forwarded.GetProperty("traceparent").GetString()!;
            var components = traceparent.Split('-');
            Assert.Equal(4, components.Length);
            Assert.Equal("00", components[0]);
            Assert.Equal("4bf92f3577b34da6a3ce929d0e0e4736", components[1]);
            Assert.NotEqual("00f067aa0ba902b7", components[2]);
            Assert.NotEqual("00f067aa0ba902b7", response.Headers.GetValues("X-Span-Id").Single());
            Assert.NotEqual(components[2], response.Headers.GetValues("X-Span-Id").Single());
        }
        finally
        {
            await downstream.StopAsync();
        }
    }

    [Fact]
    public async Task GatewayGeneratesAndForwardsCorrelationIdWhenMissingOrInvalid()
    {
        var downstreamBuilder = WebApplication.CreateBuilder();
        downstreamBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var downstream = downstreamBuilder.Build();
        downstream.MapGet("/{**path}", (HttpContext context) => Results.Text(context.Request.Headers["X-Correlation-ID"].ToString()));
        await downstream.StartAsync();

        try
        {
            var server = downstream.Services.GetRequiredService<IServer>();
            var destination = server.Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            using var factory = GatewayTestSecurity.CreateGatewayFactory(destination, destination);

            var adminToken = GatewayTestSecurity.CreateAdminToken(Guid.NewGuid(), "admin");
            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
            client.DefaultRequestHeaders.Add("X-Correlation-ID", "invalid id with spaces");
            using var response = await client.GetAsync("/assets/app.js");
            response.EnsureSuccessStatusCode();

            var returnedId = response.Headers.GetValues("X-Correlation-ID").Single();
            Assert.Matches("^[A-Fa-f0-9]{32}$", returnedId);
            Assert.Equal(returnedId, await response.Content.ReadAsStringAsync());

            client.DefaultRequestHeaders.Remove("X-Correlation-ID");
            using var missingHeaderResponse = await client.GetAsync("/assets/app.css");
            missingHeaderResponse.EnsureSuccessStatusCode();
            var generatedId = missingHeaderResponse.Headers.GetValues("X-Correlation-ID").Single();
            Assert.Matches("^[A-Fa-f0-9]{32}$", generatedId);
            Assert.Equal(generatedId, await missingHeaderResponse.Content.ReadAsStringAsync());
            Assert.NotEqual(returnedId, generatedId);
        }
        finally
        {
            await downstream.StopAsync();
        }
    }
}
