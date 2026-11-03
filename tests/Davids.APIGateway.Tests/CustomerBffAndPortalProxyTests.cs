using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
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

[Trait("Category", "Integration")]
public sealed class CustomerBffAndPortalProxyTests
{
    [Fact]
    public async Task CustomerBffPkceChallengePortalProxyHostRoutingAndCsrfIsolationWorkEndToEnd()
    {
        var webBuilder = WebApplication.CreateBuilder();
        webBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var frontendWeb = webBuilder.Build();
        frontendWeb.MapGet("/{**path}", (HttpContext ctx) => Results.Json(new
        {
            path = ctx.Request.Path.Value,
            auth = ctx.Request.Headers.Authorization.ToString(),
            cookie = ctx.Request.Headers.Cookie.ToString()
        }));
        await frontendWeb.StartAsync();

        try
        {
            var webAddress = frontendWeb.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!.Addresses.Single();

            using var factory = GatewayTestSecurity.CreateGatewayFactory(
                backendDestination: webAddress,
                frontendDestination: "http://127.0.0.1:9/",
                frontendWebDestination: webAddress);
            using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });

            // 1. /customer-auth/login issues PKCE S256 redirect to /identity/connect/authorize with isolated cookies.
            using var loginResp = await client.GetAsync("/customer-auth/login?returnUrl=%2Fportal");
            Assert.Equal(HttpStatusCode.Found, loginResp.StatusCode);
            var redirectLocation = loginResp.Headers.Location?.ToString() ?? string.Empty;
            Assert.Contains("/identity/connect/authorize", redirectLocation, StringComparison.Ordinal);
            Assert.Contains("client_id=davids-web", redirectLocation, StringComparison.Ordinal);
            Assert.Contains("code_challenge_method=S256", redirectLocation, StringComparison.Ordinal);
            Assert.Contains("signin-customer-oidc", redirectLocation, StringComparison.Ordinal);
            var setCookies = string.Join(";", loginResp.Headers.GetValues("Set-Cookie"));
            Assert.Contains(GatewayAuthPolicies.CustomerOidcCorrelationCookiePrefix, setCookies, StringComparison.Ordinal);
            Assert.Contains(GatewayAuthPolicies.CustomerOidcNonceCookiePrefix, setCookies, StringComparison.Ordinal);

            // 2. Anonymous HTML GET /portal -> 302 /portal/login; Host portal.davids.test GET / -> 302 /login.
            using (var anonPortal = new HttpRequestMessage(HttpMethod.Get, "/portal"))
            {
                anonPortal.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
                using var resp = await client.SendAsync(anonPortal);
                Assert.Equal(HttpStatusCode.Found, resp.StatusCode);
                Assert.Equal("/portal/login", resp.Headers.Location?.OriginalString);
            }

            using (var anonHost = new HttpRequestMessage(HttpMethod.Get, "http://portal.davids.test/"))
            {
                anonHost.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
                using var resp = await client.SendAsync(anonHost);
                Assert.Equal(HttpStatusCode.Found, resp.StatusCode);
                Assert.Equal("/login", resp.Headers.Location?.OriginalString);
            }

            // 3. Public login shell on /portal/login reaches frontend-web as /login.
            using (var pubLogin = await client.GetAsync("/portal/login"))
            {
                Assert.Equal(HttpStatusCode.OK, pubLogin.StatusCode);
                using var doc = await JsonDocument.ParseAsync(await pubLogin.Content.ReadAsStreamAsync());
                Assert.Equal("/login", doc.RootElement.GetProperty("path").GetString());
            }

            // 4. Workforce admin token is rejected (403) on /portal/app.js; customer token succeeds (200) with stripped credentials.
            var adminToken = GatewayTestSecurity.CreateAdminToken(Guid.NewGuid(), "admin");
            using (var adminPortalReq = new HttpRequestMessage(HttpMethod.Get, "/portal/app.js"))
            {
                adminPortalReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
                Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(adminPortalReq)).StatusCode);
            }

            var customerId = Guid.NewGuid();
            var customerToken = GatewayTestSecurity.CreateCustomerToken(customerId, "user");
            using (var custPortalReq = new HttpRequestMessage(HttpMethod.Get, "/portal/app.js"))
            {
                custPortalReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", customerToken);
                custPortalReq.Headers.Add("Cookie", $"{GatewayAuthPolicies.CustomerBffCookieName}=secret");
                using var resp = await client.SendAsync(custPortalReq);
                Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
                using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
                Assert.Equal("/app.js", doc.RootElement.GetProperty("path").GetString());
                Assert.Equal(string.Empty, doc.RootElement.GetProperty("auth").GetString());
                Assert.Equal(string.Empty, doc.RootElement.GetProperty("cookie").GetString());
            }

            // 5. /customer-auth/session & /customer-auth/logout CSRF header isolation (DavidsWeb vs DavidsAdmin).
            using (var sessionReq = new HttpRequestMessage(HttpMethod.Get, "/customer-auth/session"))
            {
                sessionReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", customerToken);
                using var resp = await client.SendAsync(sessionReq);
                Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            }

            using (var wrongCsrfLogout = new HttpRequestMessage(HttpMethod.Post, "/customer-auth/logout"))
            {
                wrongCsrfLogout.Headers.Add(GatewayAuthPolicies.AdminCsrfHeaderName, GatewayAuthPolicies.AdminCsrfHeaderValue);
                Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(wrongCsrfLogout)).StatusCode);
            }

            using (var validCsrfLogout = new HttpRequestMessage(HttpMethod.Post, "/customer-auth/logout"))
            {
                validCsrfLogout.Headers.Add(GatewayAuthPolicies.AdminCsrfHeaderName, GatewayAuthPolicies.CustomerCsrfHeaderValue);
                Assert.Equal(HttpStatusCode.NoContent, (await client.SendAsync(validCsrfLogout)).StatusCode);
            }
        }
        finally
        {
            await frontendWeb.StopAsync();
        }
    }
}
