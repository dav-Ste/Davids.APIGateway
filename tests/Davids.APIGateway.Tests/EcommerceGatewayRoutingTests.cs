using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Davids.APIGateway.Tests;

[Trait("Category", "Integration")]
public sealed class EcommerceGatewayRoutingTests
{
    [Fact]
    public async Task EcommerceCatalogBasketOrderAndPaymentClustersEnforceRealmAndRbacIsolation()
    {
        static async Task<WebApplication> StartFakeClusterAsync(string clusterName)
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            var app = builder.Build();
            app.MapMethods("/{**path}", ["GET", "POST", "PUT", "DELETE"], (HttpContext ctx) =>
                Results.Json(new
                {
                    cluster = clusterName,
                    path = ctx.Request.Path.Value,
                    method = ctx.Request.Method,
                    authority = ctx.Request.Headers["X-Auth-Authority"].ToString(),
                    role = ctx.Request.Headers["X-Auth-User-Role"].ToString()
                }));
            await app.StartAsync();
            return app;
        }

        static string Addr(WebApplication app) =>
            app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();

        await using var productsCluster = await StartFakeClusterAsync("products");
        await using var basketsCluster = await StartFakeClusterAsync("baskets");
        await using var ordersCluster = await StartFakeClusterAsync("orders");
        await using var paymentsCluster = await StartFakeClusterAsync("payments");

        try
        {
            using var factory = GatewayTestSecurity.CreateGatewayFactory(
                backendDestination: Addr(productsCluster),
                productsDestination: Addr(productsCluster),
                basketsDestination: Addr(basketsCluster),
                ordersDestination: Addr(ordersCluster),
                paymentsDestination: Addr(paymentsCluster));
            using var client = factory.CreateClient();

            // 1. Public anonymous GET /products reaches products cluster
            using (var pubResp = await client.GetAsync("/products"))
            {
                Assert.Equal(HttpStatusCode.OK, pubResp.StatusCode);
                using var doc = await JsonDocument.ParseAsync(await pubResp.Content.ReadAsStreamAsync());
                Assert.Equal("products", doc.RootElement.GetProperty("cluster").GetString());
            }

            var customerToken = GatewayTestSecurity.CreateCustomerToken(Guid.NewGuid(), "user");
            var supportToken = GatewayTestSecurity.CreateAdminToken(Guid.NewGuid(), "support");
            var adminToken = GatewayTestSecurity.CreateAdminToken(Guid.NewGuid(), "admin");

            // 2. Customer accesses /baskets/me, /orders/checkout, /payments/me; blocked from workforce /orders & /payments
            foreach (var (method, path, expectedCluster) in new[]
            {
                ("GET", "/baskets/me", "baskets"),
                ("POST", "/orders/checkout", "orders"),
                ("GET", "/payments/me", "payments")
            })
            {
                using var req = new HttpRequestMessage(new HttpMethod(method), path);
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", customerToken);
                if (method == "POST")
                {
                    req.Content = JsonContent.Create(new { shippingFullName = "Alice", shippingAddress = "1 High St" });
                }

                using var resp = await client.SendAsync(req);
                Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
                using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
                Assert.Equal(expectedCluster, doc.RootElement.GetProperty("cluster").GetString());
                Assert.Equal("customer", doc.RootElement.GetProperty("authority").GetString());
            }

            foreach (var wfPath in new[] { "/products/admin", "/orders", "/payments" })
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, wfPath);
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", customerToken);
                Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(req)).StatusCode);
            }

            // 3. Workforce support can read /orders & /payments and adjust stock, cannot POST /products (admin-only), and cannot use /baskets/me
            using (var stockReq = new HttpRequestMessage(HttpMethod.Post, $"/products/{Guid.NewGuid()}/stock")
            {
                Content = JsonContent.Create(new { delta = 5, reason = "Restock" })
            })
            {
                stockReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", supportToken);
                Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(stockReq)).StatusCode);
            }

            using (var createProdSupport = new HttpRequestMessage(HttpMethod.Post, "/products")
            {
                Content = JsonContent.Create(new { sku = "SKU-1", name = "Item" })
            })
            {
                createProdSupport.Headers.Authorization = new AuthenticationHeaderValue("Bearer", supportToken);
                Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(createProdSupport)).StatusCode);
            }

            using (var createProdAdmin = new HttpRequestMessage(HttpMethod.Post, "/products")
            {
                Content = JsonContent.Create(new { sku = "SKU-1", name = "Item" })
            })
            {
                createProdAdmin.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
                Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(createProdAdmin)).StatusCode);
            }

            using (var adminBasketReq = new HttpRequestMessage(HttpMethod.Get, "/baskets/me"))
            {
                adminBasketReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
                Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(adminBasketReq)).StatusCode);
            }
        }
        finally
        {
            await productsCluster.StopAsync();
            await basketsCluster.StopAsync();
            await ordersCluster.StopAsync();
            await paymentsCluster.StopAsync();
        }
    }
}
