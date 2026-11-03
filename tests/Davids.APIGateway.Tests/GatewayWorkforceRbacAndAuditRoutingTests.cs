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

[Trait("Category", "Integration")]
public sealed class GatewayWorkforceRbacAndAuditRoutingTests
{
    [Fact]
    public async Task SupportAndAuditorRolesAreEnforcedAcrossCustomerSupportEmployeeIamAndChangeAuditRoutes()
    {
        static async Task<WebApplication> StartFakeClusterAsync(string clusterName)
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            var app = builder.Build();
            app.MapMethods("/{**path}", new[] { "GET", "POST", "PUT" }, (HttpContext context) =>
                Results.Json(new
                {
                    cluster = clusterName,
                    path = context.Request.Path.Value,
                    authority = context.Request.Headers[ReverseProxyExtensions.VerifiedAuthorityHeader].ToString(),
                    verifiedRole = context.Request.Headers[ReverseProxyExtensions.VerifiedUserRoleHeader].ToString(),
                    verifiedUserId = context.Request.Headers[ReverseProxyExtensions.VerifiedUserIdHeader].ToString()
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

            using var client = factory.CreateClient();
            var customerId = Guid.NewGuid();
            var supportToken = GatewayTestSecurity.CreateAdminToken(Guid.NewGuid(), "support");
            var auditorToken = GatewayTestSecurity.CreateAdminToken(Guid.NewGuid(), "auditor");
            var adminToken = GatewayTestSecurity.CreateAdminToken(Guid.NewGuid(), "admin");
            var customerToken = GatewayTestSecurity.CreateCustomerToken(customerId, "user");

            // 1. Auditor can read /customers, /customers/change-audits, /admin-identity/change-audits, and /customer-accounts/change-audits,
            //    and rotate own password via /admin-identity/me/password, but CANNOT mutate customers or provision employees.
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", auditorToken);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/customers")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/customers/change-audits")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/admin-identity/change-audits")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/customer-accounts/change-audits")).StatusCode);
            Assert.Equal(
                HttpStatusCode.OK,
                (await client.PutAsJsonAsync("/admin-identity/me/password", new { currentPassword = "a", newPassword = "b" })).StatusCode);

            Assert.Equal(
                HttpStatusCode.Forbidden,
                (await client.PutAsJsonAsync($"/customers/{customerId}", new { fullName = "X", address = "Y" })).StatusCode);
            Assert.Equal(
                HttpStatusCode.Forbidden,
                (await client.PostAsync($"/customer-accounts/users/{customerId}/unlock", content: null)).StatusCode);
            Assert.Equal(
                HttpStatusCode.Forbidden,
                (await client.PostAsJsonAsync("/admin-identity/users", new { email = "x@davids.local", password = "Password1234!" })).StatusCode);

            // 2. Support can mutate customer profiles AND unlock/update customer accounts via /customer-accounts/*,
            //    strip spoofed X-Auth-Authority headers, and still cannot provision employee accounts in /admin-identity/users.
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", supportToken);
            client.DefaultRequestHeaders.Remove(ReverseProxyExtensions.VerifiedAuthorityHeader);
            client.DefaultRequestHeaders.Add(ReverseProxyExtensions.VerifiedAuthorityHeader, "spoofed-root");

            using var unlockResp = await client.PostAsync($"/customer-accounts/users/{customerId}/unlock", content: null);
            Assert.Equal(HttpStatusCode.OK, unlockResp.StatusCode);
            using var unlockDoc = await JsonDocument.ParseAsync(await unlockResp.Content.ReadAsStreamAsync());
            Assert.Equal("identity", unlockDoc.RootElement.GetProperty("cluster").GetString());
            Assert.Equal($"/users/{customerId}/unlock", unlockDoc.RootElement.GetProperty("path").GetString());
            Assert.Equal("employee", unlockDoc.RootElement.GetProperty("authority").GetString());
            Assert.Equal("support", unlockDoc.RootElement.GetProperty("verifiedRole").GetString());

            Assert.Equal(
                HttpStatusCode.OK,
                (await client.PutAsJsonAsync($"/customers/{customerId}", new { fullName = "Alice", address = "Glasgow" })).StatusCode);
            Assert.Equal(
                HttpStatusCode.Forbidden,
                (await client.PostAsJsonAsync("/admin-identity/users", new { email = "x@davids.local", password = "Password1234!" })).StatusCode);

            // 3. Admin can provision/manage employee accounts.
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
            Assert.Equal(
                HttpStatusCode.OK,
                (await client.PostAsJsonAsync("/admin-identity/users", new { email = "x@davids.local", password = "Password1234!", role = "support" })).StatusCode);

            // 4. Customer can access /customers/me with stamped authority=customer, and is blocked from /customer-accounts/* and /customers/change-audits.
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", customerToken);
            using var meResp = await client.GetAsync("/customers/me");
            Assert.Equal(HttpStatusCode.OK, meResp.StatusCode);
            using var meDoc = await JsonDocument.ParseAsync(await meResp.Content.ReadAsStreamAsync());
            Assert.Equal("customers", meDoc.RootElement.GetProperty("cluster").GetString());
            Assert.Equal("/customers/me", meDoc.RootElement.GetProperty("path").GetString());
            Assert.Equal("customer", meDoc.RootElement.GetProperty("authority").GetString());

            Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/customers/change-audits")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/customer-accounts/change-audits")).StatusCode);
        }
        finally
        {
            await identityCluster.StopAsync();
            await adminIdentityCluster.StopAsync();
            await customersCluster.StopAsync();
        }
    }
}
