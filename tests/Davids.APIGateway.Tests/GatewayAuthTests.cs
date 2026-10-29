using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Davids.APIGateway.Infrastructure;
using Davids.APIGateway.Infrastructure.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Davids.APIGateway.Tests;

public sealed class GatewayAuthTests
{
    private sealed class FakeRevocation(
        IEnumerable<string> revokedCustomerIds = null,
        IEnumerable<string> revokedAdminIds = null) : IGatewayTokenRevocation
    {
        private readonly HashSet<string> revokedCustomers = new(revokedCustomerIds ?? [], StringComparer.Ordinal);
        private readonly HashSet<string> revokedAdmins = new(revokedAdminIds ?? [], StringComparer.Ordinal);

        public Task<bool> IsRevokedAsync(string tokenId, CancellationToken cancellationToken = default)
            => Task.FromResult(string.IsNullOrWhiteSpace(tokenId) || revokedCustomers.Contains(tokenId));

        public Task<bool> IsAdminRevokedAsync(string tokenId, CancellationToken cancellationToken = default)
            => Task.FromResult(string.IsNullOrWhiteSpace(tokenId) || revokedAdmins.Contains(tokenId));
    }

    [Theory]
    [InlineData("POST", "/identity/sign-up", "/sign-up")]
    [InlineData("GET", "/identity/.well-known/openid-configuration", "/.well-known/openid-configuration")]
    [InlineData("GET", "/identity/.well-known/jwks", "/.well-known/jwks")]
    [InlineData("GET", "/identity/connect/authorize", "/connect/authorize")]
    [InlineData("POST", "/identity/connect/token", "/connect/token")]
    [InlineData("POST", "/identity/connect/revocation", "/connect/revocation")]
    [InlineData("GET", "/admin-identity/.well-known/openid-configuration", "/.well-known/openid-configuration")]
    [InlineData("GET", "/admin-identity/.well-known/jwks", "/.well-known/jwks")]
    [InlineData("GET", "/admin-identity/connect/authorize", "/connect/authorize")]
    [InlineData("POST", "/admin-identity/connect/token", "/connect/token")]
    [InlineData("POST", "/admin-identity/connect/revocation", "/connect/revocation")]
    public async Task ExplicitPublicOidcProtocolRoutesAllowAnonymousRequestsAndStripSpoofedAuthHeaders(
        string method,
        string path,
        string expectedDownstreamPath)
    {
        var downstreamHits = 0;
        var downstreamBuilder = WebApplication.CreateBuilder();
        downstreamBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var downstream = downstreamBuilder.Build();
        downstream.MapMethods("/{**path}", ["GET", "POST"], (HttpContext context) =>
        {
            Interlocked.Increment(ref downstreamHits);
            return Results.Json(new
            {
                path = context.Request.Path.Value,
                spoofedUser = context.Request.Headers[ReverseProxyExtensions.VerifiedUserIdHeader].ToString(),
                spoofedRole = context.Request.Headers[ReverseProxyExtensions.VerifiedUserRoleHeader].ToString()
            });
        });
        await downstream.StartAsync();

        try
        {
            var address = downstream.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            using var factory = GatewayTestSecurity.CreateGatewayFactory(address);
            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Add(ReverseProxyExtensions.VerifiedUserIdHeader, "attacker");
            client.DefaultRequestHeaders.Add(ReverseProxyExtensions.VerifiedUserRoleHeader, "admin");

            using var request = new HttpRequestMessage(new HttpMethod(method), path);
            if (method == "POST")
            {
                request.Content = JsonContent.Create(new { sample = true });
            }

            using var response = await client.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(1, downstreamHits);

            using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
            Assert.Equal(expectedDownstreamPath, doc.RootElement.GetProperty("path").GetString());
            Assert.Equal(string.Empty, doc.RootElement.GetProperty("spoofedUser").GetString());
            Assert.Equal(string.Empty, doc.RootElement.GetProperty("spoofedRole").GetString());
        }
        finally
        {
            await downstream.StopAsync();
        }
    }

    [Fact]
    public async Task AdminIdentityHasNoPublicSignUpRouteAndUserInfoRequiresVerifiedToken()
    {
        var downstreamHits = 0;
        var downstreamBuilder = WebApplication.CreateBuilder();
        downstreamBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var downstream = downstreamBuilder.Build();
        downstream.MapMethods("/{**path}", ["GET", "POST"], () =>
        {
            Interlocked.Increment(ref downstreamHits);
            return Results.Ok();
        });
        await downstream.StartAsync();

        try
        {
            var address = downstream.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            using var factory = GatewayTestSecurity.CreateGatewayFactory(address);
            using var client = factory.CreateClient();

            using var anonSignUp = await client.PostAsJsonAsync("/admin-identity/sign-up", new { email = "x@davids.local" });
            Assert.Equal(HttpStatusCode.Unauthorized, anonSignUp.StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/identity/connect/userinfo")).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/admin-identity/connect/userinfo")).StatusCode);

            var customerToken = GatewayTestSecurity.CreateCustomerToken(Guid.NewGuid(), "user");
            using var custUsers = new HttpRequestMessage(HttpMethod.Post, "/admin-identity/users");
            custUsers.Headers.Authorization = new AuthenticationHeaderValue("Bearer", customerToken);
            custUsers.Content = JsonContent.Create(new { email = "x@davids.local" });
            Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(custUsers)).StatusCode);
            Assert.Equal(0, downstreamHits);
        }
        finally
        {
            await downstream.StopAsync();
        }
    }

    [Fact]
    public async Task PublicHealthAndGatewayInfoEndpointsAllowAnonymousRequests()
    {
        using var factory = GatewayTestSecurity.CreateGatewayFactory("http://127.0.0.1:9/");
        using var client = factory.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/alive")).StatusCode);

        using var info = await client.GetAsync("/gateway-info");
        Assert.Equal(HttpStatusCode.OK, info.StatusCode);
        using var payload = await JsonDocument.ParseAsync(await info.Content.ReadAsStreamAsync());
        Assert.Contains("RS256 JWKS", payload.RootElement.GetProperty("authentication").GetString());
    }

    [Fact]
    public async Task MissingMalformedSymmetricWrongRsaKeyCrossSchemeExpiredAndIncompleteTokensAreRejectedAtGateway()
    {
        var downstreamHits = 0;
        var downstreamBuilder = WebApplication.CreateBuilder();
        downstreamBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var downstream = downstreamBuilder.Build();
        downstream.MapMethods("/{**path}", ["GET", "POST", "PUT"], () =>
        {
            Interlocked.Increment(ref downstreamHits);
            return Results.Ok();
        });
        await downstream.StartAsync();

        try
        {
            var address = downstream.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            using var factory = GatewayTestSecurity.CreateGatewayFactory(address);
            using var client = factory.CreateClient();

            var userId = Guid.NewGuid();
            using var rogueRsa = RSA.Create(2048);
            var rogueKey = new RsaSecurityKey(rogueRsa.ExportParameters(true)) { KeyId = "rogue-kid" };

            var hs256Token = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
                issuer: GatewayTestSecurity.CustomerIssuer,
                audience: GatewayTestSecurity.CustomerAudience,
                claims:
                [
                    new Claim("sub", userId.ToString("N")),
                    new Claim("role", "user"),
                    new Claim("jti", Guid.NewGuid().ToString("N"))
                ],
                notBefore: DateTime.UtcNow.AddSeconds(-5),
                expires: DateTime.UtcNow.AddMinutes(5),
                signingCredentials: new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes("legacy-hs256-symmetric-key-must-be-rejected-123456")),
                    SecurityAlgorithms.HmacSha256)));

            var invalidTokens = new[]
            {
                null,
                "not-a-jwt",
                hs256Token, // HS256 symmetric tokens are never accepted
                GatewayTestSecurity.CreateCustomerToken(userId, signingKey: rogueKey),
                GatewayTestSecurity.CreateCustomerToken(userId, role: "admin"),
                GatewayTestSecurity.CreateAdminToken(userId, signingKey: GatewayTestSecurity.CustomerPrivateKey),
                GatewayTestSecurity.CreateCustomerToken(userId, issuer: "https://wrong-issuer.test/"),
                GatewayTestSecurity.CreateCustomerToken(userId, audience: "wrong-audience"),
                GatewayTestSecurity.CreateCustomerToken(
                    userId,
                    notBeforeUtc: DateTime.UtcNow.AddMinutes(-20),
                    expiresUtc: DateTime.UtcNow.AddMinutes(-5)),
                GatewayTestSecurity.CreateCustomerToken(userId, includeTokenId: false),
                GatewayTestSecurity.CreateCustomerToken(userId, includeSubject: false)
            };

            foreach (var candidate in invalidTokens)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"/customers/{userId}");
                if (candidate is not null)
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", candidate);
                }

                using var response = await client.SendAsync(request);
                Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
                Assert.Contains("Bearer", response.Headers.WwwAuthenticate.ToString());
                using var error = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
                Assert.Equal("unauthenticated", error.RootElement.GetProperty("code").GetString());
            }

            Assert.Equal(0, downstreamHits);
        }
        finally
        {
            await downstream.StopAsync();
        }
    }

    [Fact]
    public async Task ResourceOwnerOrAdminPolicyBlocksCrossUserAccessAndAllowsOwnerOrAdmin()
    {
        var downstreamHits = 0;
        var downstreamBuilder = WebApplication.CreateBuilder();
        downstreamBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var downstream = downstreamBuilder.Build();
        downstream.MapGet("/{**path}", (HttpContext context) =>
        {
            Interlocked.Increment(ref downstreamHits);
            return Results.Ok(new { path = context.Request.Path.Value });
        });
        await downstream.StartAsync();

        try
        {
            var address = downstream.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            using var factory = GatewayTestSecurity.CreateGatewayFactory(address);
            using var client = factory.CreateClient();

            var ownerId = Guid.NewGuid();
            var otherUserId = Guid.NewGuid();
            var adminId = Guid.NewGuid();

            var ownerToken = GatewayTestSecurity.CreateCustomerToken(ownerId, "user");
            var otherToken = GatewayTestSecurity.CreateCustomerToken(otherUserId, "user");
            var adminToken = GatewayTestSecurity.CreateAdminToken(adminId, "admin");

            var customerAndAdminRoutes = new[]
            {
                $"/customers/{ownerId:D}",
                $"/customers/{ownerId:D}/state"
            };
            var customerSelfOnlyRoute = $"/identity/users/{ownerId:D}";

            foreach (var route in customerAndAdminRoutes.Append(customerSelfOnlyRoute))
            {
                using var crossUserRequest = new HttpRequestMessage(HttpMethod.Get, route);
                crossUserRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", otherToken);
                using var forbidden = await client.SendAsync(crossUserRequest);
                Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
                using var body = await JsonDocument.ParseAsync(await forbidden.Content.ReadAsStreamAsync());
                Assert.Equal("forbidden", body.RootElement.GetProperty("code").GetString());
            }

            using (var adminToCustomerIdentity = new HttpRequestMessage(HttpMethod.Get, customerSelfOnlyRoute))
            {
                adminToCustomerIdentity.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
                Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(adminToCustomerIdentity)).StatusCode);
            }

            Assert.Equal(0, downstreamHits);

            using (var ownerIdentityReq = new HttpRequestMessage(HttpMethod.Get, customerSelfOnlyRoute))
            {
                ownerIdentityReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ownerToken);
                Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(ownerIdentityReq)).StatusCode);
            }

            foreach (var route in customerAndAdminRoutes)
            {
                using var ownerRequest = new HttpRequestMessage(HttpMethod.Get, route);
                ownerRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ownerToken);
                Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(ownerRequest)).StatusCode);

                using var adminRequest = new HttpRequestMessage(HttpMethod.Get, route);
                adminRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
                Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(adminRequest)).StatusCode);
            }

            Assert.Equal(1 + (customerAndAdminRoutes.Length * 2), downstreamHits);
        }
        finally
        {
            await downstream.StopAsync();
        }
    }

    [Fact]
    public async Task AdminOnlyRoutesRejectNonAdminUsersIncludingTrailingSlash()
    {
        var downstreamHits = 0;
        var downstreamBuilder = WebApplication.CreateBuilder();
        downstreamBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var downstream = downstreamBuilder.Build();
        downstream.MapMethods("/{**path}", ["GET", "PUT"], (HttpContext context) =>
        {
            Interlocked.Increment(ref downstreamHits);
            return Results.Ok(new { path = context.Request.Path.Value });
        });
        await downstream.StartAsync();

        try
        {
            var address = downstream.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            using var factory = GatewayTestSecurity.CreateGatewayFactory(address);
            using var client = factory.CreateClient();

            var customerId = Guid.NewGuid();
            var userToken = GatewayTestSecurity.CreateCustomerToken(customerId, "user");
            var adminToken = GatewayTestSecurity.CreateAdminToken(Guid.NewGuid(), "admin");

            var adminEndpoints = new (HttpMethod Method, string Path)[]
            {
                (HttpMethod.Get, "/admin-identity/me"),
                (HttpMethod.Get, "/admin-identity/users"),
                (HttpMethod.Get, "/customers"),
                (HttpMethod.Get, "/customers/"),
                (HttpMethod.Get, "/customers?search=jane&state=valid&vip=true"),
                (HttpMethod.Put, $"/customers/{customerId}"),
                (HttpMethod.Put, $"/customers/{customerId}/"),
                (HttpMethod.Put, $"/customers/{customerId}/state/locked")
            };

            foreach (var (method, path) in adminEndpoints)
            {
                using var anonymousRequest = new HttpRequestMessage(method, path);
                Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(anonymousRequest)).StatusCode);

                using var userRequest = new HttpRequestMessage(method, path);
                userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", userToken);
                if (method == HttpMethod.Put)
                {
                    userRequest.Content = JsonContent.Create(new
                    {
                        customerId,
                        fullName = "Jane Doe",
                        address = "1 Main Street",
                        email = "jane@example.com",
                        state = "locked"
                    });
                }

                Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(userRequest)).StatusCode);
            }

            Assert.Equal(0, downstreamHits);

            foreach (var (method, path) in adminEndpoints)
            {
                using var adminRequest = new HttpRequestMessage(method, path);
                adminRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
                if (method == HttpMethod.Put)
                {
                    adminRequest.Content = JsonContent.Create(new
                    {
                        customerId,
                        fullName = "Jane Doe",
                        address = "1 Main Street",
                        email = "jane@example.com",
                        state = "locked"
                    });
                }

                using var response = await client.SendAsync(adminRequest);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            }

            Assert.Equal(adminEndpoints.Length, downstreamHits);
        }
        finally
        {
            await downstream.StopAsync();
        }
    }

    [Fact]
    public async Task AdminOidcBffPerformsPkceCodeExchangeIssuesEncryptedCookieEnforcesCsrfAndRevokesOnLogout()
    {
        string forwardedAuthHeader = null;
        string forwardedCookieHeader = null;
        string forwardedSchemeHeader = null;
        string capturedCodeChallenge = null;
        string capturedNonce = null;
        var revokedTokens = new List<(string Token, string Hint)>();

        var adminId = Guid.NewGuid();
        string issuedAccessJwt = null;

        var oidcBuilder = WebApplication.CreateBuilder();
        oidcBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var oidcServer = oidcBuilder.Build();

        string oidcBaseUrl = null;
        oidcServer.MapGet("/.well-known/openid-configuration", () => Results.Json(new
        {
            issuer = oidcBaseUrl,
            authorization_endpoint = oidcBaseUrl + "connect/authorize",
            token_endpoint = oidcBaseUrl + "connect/token",
            revocation_endpoint = oidcBaseUrl + "connect/revocation",
            jwks_uri = oidcBaseUrl + ".well-known/jwks",
            response_types_supported = new[] { "code" },
            grant_types_supported = new[] { "authorization_code", "refresh_token" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            code_challenge_methods_supported = new[] { "S256" }
        }));

        oidcServer.MapGet("/.well-known/jwks", () =>
        {
            var rsaParams = GatewayTestSecurity.AdminRsa.ExportParameters(false);
            return Results.Json(new
            {
                keys = new[]
                {
                    new
                    {
                        kty = "RSA",
                        use = "sig",
                        alg = "RS256",
                        kid = GatewayTestSecurity.AdminPrivateKey.KeyId,
                        n = Base64UrlEncoder.Encode(rsaParams.Modulus),
                        e = Base64UrlEncoder.Encode(rsaParams.Exponent)
                    }
                }
            });
        });

        oidcServer.MapGet("/connect/authorize", (HttpContext ctx) =>
        {
            Assert.NotEqual("form_post", ctx.Request.Query["response_mode"].ToString());
            return Results.Content("<form method=\"post\" action=\"authorize\"></form>", "text/html; charset=utf-8");
        });

        oidcServer.MapPost("/connect/authorize", async (HttpContext ctx) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            Assert.NotEqual("form_post", form["response_mode"].ToString());
            var redirectUri = form["redirect_uri"].ToString();
            var formState = form["state"].ToString();
            var callbackWithCode =
                $"{redirectUri}?code=test-auth-code-123&state={Uri.EscapeDataString(formState)}&iss={Uri.EscapeDataString(oidcBaseUrl)}";
            return Results.Redirect(callbackWithCode);
        });

        oidcServer.MapPost("/connect/token", async (HttpContext ctx) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            Assert.Equal("authorization_code", form["grant_type"].ToString());
            Assert.Equal(GatewayTestSecurity.BffClientId, form["client_id"].ToString());
            Assert.Equal(GatewayTestSecurity.BffClientSecret, form["client_secret"].ToString());
            Assert.Equal("test-auth-code-123", form["code"].ToString());

            // Verify PKCE S256 code_verifier matches the code_challenge sent on /auth/login!
            var verifier = form["code_verifier"].ToString();
            Assert.False(string.IsNullOrWhiteSpace(verifier));
            var computedChallenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
            Assert.Equal(capturedCodeChallenge, computedChallenge);

            issuedAccessJwt = GatewayTestSecurity.CreateAdminToken(
                adminId,
                "admin",
                tokenId: "bff-jti-001",
                issuer: oidcBaseUrl);
            var idToken = GatewayTestSecurity.CreateAdminIdToken(
                adminId,
                capturedNonce,
                issuer: oidcBaseUrl);

            return Results.Json(new
            {
                access_token = issuedAccessJwt,
                id_token = idToken,
                refresh_token = "bff-refresh-token-001",
                token_type = "Bearer",
                expires_in = 900
            });
        });

        oidcServer.MapPost("/connect/revocation", async (HttpContext ctx) =>
        {
            var form = await ctx.Request.ReadFormAsync();
            Assert.Equal(GatewayTestSecurity.BffClientId, form["client_id"].ToString());
            Assert.Equal(GatewayTestSecurity.BffClientSecret, form["client_secret"].ToString());
            revokedTokens.Add((form["token"].ToString(), form["token_type_hint"].ToString()));
            return Results.Ok();
        });

        var customersBuilder = WebApplication.CreateBuilder();
        customersBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var customersDownstream = customersBuilder.Build();
        customersDownstream.MapMethods("/{**path}", ["GET", "PUT"], (HttpContext ctx) =>
        {
            forwardedAuthHeader = ctx.Request.Headers.Authorization.ToString();
            forwardedCookieHeader = ctx.Request.Headers.Cookie.ToString();
            forwardedSchemeHeader = ctx.Request.Headers[ReverseProxyExtensions.VerifiedSchemeHeader].ToString();
            return Results.Ok(new { ok = true });
        });

        await oidcServer.StartAsync();
        await customersDownstream.StartAsync();

        try
        {
            oidcBaseUrl = oidcServer.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!.Addresses.Single().TrimEnd('/') + "/";
            var customersAddress = customersDownstream.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!.Addresses.Single();

            using var factory = GatewayTestSecurity.CreateGatewayFactory(
                backendDestination: customersAddress,
                adminIdentityDestination: oidcBaseUrl,
                customersDestination: customersAddress,
                adminAuthority: oidcBaseUrl);
            using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false
            });

            // 1. Initiate OIDC BFF login -> redirects to /admin-identity/connect/authorize with PKCE S256 + correlation/nonce cookies.
            using var loginChallenge = await client.GetAsync("/auth/login?returnUrl=%2F");
            Assert.Equal(HttpStatusCode.Redirect, loginChallenge.StatusCode);
            var redirectLocation = loginChallenge.Headers.Location!;
            Assert.Equal("/admin-identity/connect/authorize", redirectLocation.AbsolutePath);

            var authorizeParams = QueryHelpers.ParseQuery(redirectLocation.Query);
            Assert.Equal(GatewayTestSecurity.BffClientId, authorizeParams["client_id"].ToString());
            Assert.Equal("code", authorizeParams["response_type"].ToString());
            Assert.False(
                authorizeParams.TryGetValue("response_mode", out var responseModeVal) &&
                string.Equals(responseModeVal.ToString(), "form_post", StringComparison.OrdinalIgnoreCase),
                "Gateway BFF must never request response_mode=form_post under CSP script-src 'self'.");
            Assert.Equal("S256", authorizeParams["code_challenge_method"].ToString());
            capturedCodeChallenge = authorizeParams["code_challenge"].ToString();
            capturedNonce = authorizeParams["nonce"].ToString();
            var state = authorizeParams["state"].ToString();
            var redirectUriParam = authorizeParams["redirect_uri"].ToString();
            Assert.False(string.IsNullOrWhiteSpace(capturedCodeChallenge));

            var oidcChallengeCookies = loginChallenge.Headers.GetValues("Set-Cookie")
                .Select(raw => raw.Split(';', 2)[0])
                .ToArray();
            Assert.NotEmpty(oidcChallengeCookies);

            // 1b. Browser loads GET /admin-identity/connect/authorize and submits POST /admin-identity/connect/authorize -> 302 Found to /signin-oidc (never a 200 form_post blank screen).
            using var getAuthorizeRes = await client.GetAsync(redirectLocation.PathAndQuery);
            Assert.Equal(HttpStatusCode.OK, getAuthorizeRes.StatusCode);

            using var postAuthorizeRes = await client.PostAsync(
                "/admin-identity/connect/authorize",
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["client_id"] = GatewayTestSecurity.BffClientId,
                    ["redirect_uri"] = redirectUriParam,
                    ["response_type"] = "code",
                    ["code_challenge"] = capturedCodeChallenge,
                    ["code_challenge_method"] = "S256",
                    ["nonce"] = capturedNonce,
                    ["state"] = state,
                    ["email"] = "admin@davids.local",
                    ["password"] = "Admin-Strong-Pass-123!"
                }));
            Assert.Equal(HttpStatusCode.Redirect, postAuthorizeRes.StatusCode);
            var callbackUri = postAuthorizeRes.Headers.Location!;
            Assert.Equal("/signin-oidc", callbackUri.AbsolutePath);

            // 2. Callback /signin-oidc redeems code + PKCE verifier via back-channel and issues HttpOnly encrypted davids_admin_bff cookie.
            using var callbackReq = new HttpRequestMessage(
                HttpMethod.Get,
                callbackUri.PathAndQuery);
            callbackReq.Headers.Add("Cookie", string.Join("; ", oidcChallengeCookies));
            using var callbackRes = await client.SendAsync(callbackReq);
            Assert.Equal(HttpStatusCode.Redirect, callbackRes.StatusCode);
            Assert.Equal("/", callbackRes.Headers.Location?.OriginalString);

            var bffSetCookie = callbackRes.Headers.GetValues("Set-Cookie")
                .Single(c => c.StartsWith($"{GatewayAuthPolicies.AdminBffCookieName}=", StringComparison.Ordinal));
            Assert.Contains("httponly", bffSetCookie, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(issuedAccessJwt, bffSetCookie, StringComparison.Ordinal); // Encrypted ticket, never raw JWT!
            var bffCookieHeader = bffSetCookie.Split(';', 2)[0];

            // 3. GET /auth/session returns authenticated admin metadata.
            using var sessionReq = new HttpRequestMessage(HttpMethod.Get, "/auth/session");
            sessionReq.Headers.Add("Cookie", bffCookieHeader);
            using var sessionRes = await client.SendAsync(sessionReq);
            Assert.Equal(HttpStatusCode.OK, sessionRes.StatusCode);
            using var sessionDoc = await JsonDocument.ParseAsync(await sessionRes.Content.ReadAsStreamAsync());
            Assert.Equal("oidc-bff", sessionDoc.RootElement.GetProperty("authMethod").GetString());
            Assert.Equal("admin@davids.local", sessionDoc.RootElement.GetProperty("email").GetString());

            // 4. GET /customers with BFF cookie injects RS256 Bearer token and strips Cookie header downstream!
            using var getCustomers = new HttpRequestMessage(HttpMethod.Get, "/customers");
            getCustomers.Headers.Add("Cookie", bffCookieHeader);
            Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(getCustomers)).StatusCode);
            Assert.Equal($"Bearer {issuedAccessJwt}", forwardedAuthHeader);
            Assert.Equal(string.Empty, forwardedCookieHeader);
            Assert.Equal(GatewayAuthPolicies.AdminBffCookieScheme, forwardedSchemeHeader);

            // 5. Unsafe PUT /customers/{id} WITHOUT X-Requested-With CSRF header is rejected with 403 csrf_rejected!
            var cid = Guid.NewGuid();
            using var csrfMissingPut = new HttpRequestMessage(HttpMethod.Put, $"/customers/{cid}");
            csrfMissingPut.Headers.Add("Cookie", bffCookieHeader);
            csrfMissingPut.Content = JsonContent.Create(new { customerId = cid });
            using var csrfRejectedRes = await client.SendAsync(csrfMissingPut);
            Assert.Equal(HttpStatusCode.Forbidden, csrfRejectedRes.StatusCode);

            // 6. Unsafe PUT /customers/{id} WITH X-Requested-With: DavidsAdmin succeeds!
            using var csrfValidPut = new HttpRequestMessage(HttpMethod.Put, $"/customers/{cid}");
            csrfValidPut.Headers.Add("Cookie", bffCookieHeader);
            csrfValidPut.Headers.Add(GatewayAuthPolicies.AdminCsrfHeaderName, GatewayAuthPolicies.AdminCsrfHeaderValue);
            csrfValidPut.Content = JsonContent.Create(new { customerId = cid });
            Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(csrfValidPut)).StatusCode);

            // 7. POST /auth/logout WITHOUT CSRF header is rejected with 403; WITH CSRF header revokes tokens and clears cookie!
            using var csrfMissingLogout = new HttpRequestMessage(HttpMethod.Post, "/auth/logout");
            csrfMissingLogout.Headers.Add("Cookie", bffCookieHeader);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(csrfMissingLogout)).StatusCode);

            using var validLogout = new HttpRequestMessage(HttpMethod.Post, "/auth/logout");
            validLogout.Headers.Add("Cookie", bffCookieHeader);
            validLogout.Headers.Add(GatewayAuthPolicies.AdminCsrfHeaderName, GatewayAuthPolicies.AdminCsrfHeaderValue);
            using var logoutRes = await client.SendAsync(validLogout);
            Assert.Equal(HttpStatusCode.NoContent, logoutRes.StatusCode);
            Assert.Contains(revokedTokens, r => r.Token == "bff-refresh-token-001" && r.Hint == "refresh_token");
            Assert.Contains(revokedTokens, r => r.Token == issuedAccessJwt && r.Hint == "access_token");
            Assert.Contains(
                logoutRes.Headers.GetValues("Set-Cookie"),
                c => c.StartsWith($"{GatewayAuthPolicies.AdminBffCookieName}=", StringComparison.Ordinal) &&
                     c.Contains("1970", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            await oidcServer.StopAsync();
            await customersDownstream.StopAsync();
        }
    }

    [Fact]
    public async Task RevokedCustomerAndAdminAccessTokensAreRejectedAtGateway()
    {
        var downstreamHits = 0;
        var downstreamBuilder = WebApplication.CreateBuilder();
        downstreamBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var downstream = downstreamBuilder.Build();
        downstream.MapGet("/{**path}", () =>
        {
            Interlocked.Increment(ref downstreamHits);
            return Results.Ok();
        });
        await downstream.StartAsync();

        try
        {
            var address = downstream.Services.GetRequiredService<IServer>()
                .Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            using var factory = GatewayTestSecurity.CreateGatewayFactory(
                address,
                address,
                revocation: new FakeRevocation(
                    revokedCustomerIds: ["revoked-cust-001"],
                    revokedAdminIds: ["revoked-admin-001"]));
            using var client = factory.CreateClient();

            var userId = Guid.NewGuid();
            var revokedCustomerToken = GatewayTestSecurity.CreateCustomerToken(userId, "user", tokenId: "revoked-cust-001");
            var activeCustomerToken = GatewayTestSecurity.CreateCustomerToken(userId, "user", tokenId: "active-cust-002");

            var adminId = Guid.NewGuid();
            var revokedAdminToken = GatewayTestSecurity.CreateAdminToken(adminId, "admin", tokenId: "revoked-admin-001");
            var activeAdminToken = GatewayTestSecurity.CreateAdminToken(adminId, "admin", tokenId: "active-admin-002");

            foreach (var path in new[] { "/identity/me", $"/customers/{userId}" })
            {
                using var revokedRequest = new HttpRequestMessage(HttpMethod.Get, path);
                revokedRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", revokedCustomerToken);
                Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(revokedRequest)).StatusCode);
            }

            foreach (var path in new[] { "/app.js", "/admin-identity/me", "/customers" })
            {
                using var revokedAdminReq = new HttpRequestMessage(HttpMethod.Get, path);
                revokedAdminReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", revokedAdminToken);
                Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(revokedAdminReq)).StatusCode);
            }

            Assert.Equal(0, downstreamHits);

            foreach (var path in new[] { "/identity/me", $"/customers/{userId}" })
            {
                using var activeRequest = new HttpRequestMessage(HttpMethod.Get, path);
                activeRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", activeCustomerToken);
                Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(activeRequest)).StatusCode);
            }

            foreach (var path in new[] { "/app.js", "/admin-identity/me", "/customers" })
            {
                using var activeAdminReq = new HttpRequestMessage(HttpMethod.Get, path);
                activeAdminReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", activeAdminToken);
                Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(activeAdminReq)).StatusCode);
            }

            Assert.Equal(5, downstreamHits);
        }
        finally
        {
            await downstream.StopAsync();
        }
    }

    [Fact]
    public async Task GatewayOidcAndVaultValidationFailClosedWhenMisconfigured()
    {
        var missingAuthority = new GatewayOidcAuthoritySettings();
        Assert.Throws<InvalidOperationException>(() =>
            missingAuthority.ValidateAndResolveStaticPublicKey("CustomerOidc"));

        var privateKeySettings = new GatewayOidcAuthoritySettings
        {
            PublicKeyPem = GatewayTestSecurity.CustomerRsa.ExportPkcs8PrivateKeyPem()
        };
        Assert.Throws<InvalidOperationException>(() =>
            privateKeySettings.ValidateAndResolveStaticPublicKey("CustomerOidc"));

        var sharedPublicKey = new GatewayAdminOidcSettings
        {
            PublicKeyPem = GatewayTestSecurity.CustomerPublicKeyPem,
            BffClientSecret = GatewayTestSecurity.BffClientSecret
        };
        Assert.Throws<InvalidOperationException>(() =>
            sharedPublicKey.ValidateAdminSettings(GatewayTestSecurity.CustomerPublicKeyPem));

        var vaultConfig = new ConfigurationManager();
        vaultConfig["Vault:Enabled"] = "true";
        vaultConfig["Vault:Address"] = "http://127.0.0.1:1";
        await Assert.ThrowsAsync<InvalidOperationException>(() => vaultConfig.LoadVaultAsync());

        using var json = JsonDocument.Parse(
            """{"AdminOidc":{"BffClientSecret":"secret-value-at-least-24-chars"},"DataProtection":{"MasterKey":"0123456789abcdef0123456789abcdef"},"ConnectionStrings":{"cache":"localhost:6379"}}""");
        var values = VaultConfiguration.Flatten(json.RootElement);
        Assert.Equal("secret-value-at-least-24-chars", values["AdminOidc:BffClientSecret"]);
        Assert.Equal("0123456789abcdef0123456789abcdef", values["DataProtection:MasterKey"]);
        Assert.Equal("localhost:6379", values["ConnectionStrings:cache"]);
    }

    [Fact]
    public void GatewayDataProtectionKeyRingPersistsEncryptedKeysAndSurvivesReplicaRestart()
    {
        var sharedStore = new InMemoryGatewayDataProtectionStore();
        const string gatewayMasterKey = "gateway-bff-dp-master-wrapping-key-32-chars+!";

        string protectedCookiePayload;
        using (var replicaABase = GatewayTestSecurity.CreateGatewayFactory(
                   backendDestination: "http://127.0.0.1:9/",
                   configureServices: services => services.AddSingleton<IGatewayDataProtectionStore>(sharedStore)))
        using (var replicaA = replicaABase.WithWebHostBuilder(wb =>
                   wb.UseSetting("DataProtection:MasterKey", gatewayMasterKey)))
        {
            using var _ = replicaA.CreateClient();
            var dpA = Microsoft.AspNetCore.DataProtection.DataProtectionCommonExtensions.CreateProtector(
                replicaA.Services.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>(),
                "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware",
                GatewayAuthPolicies.AdminBffCookieScheme,
                "v2");
            protectedCookiePayload = dpA.Protect("encrypted-admin-bff-ticket");
        }

        // Raw XML stored in Redis/store must be AES-256-GCM encrypted (<encryptedKey>), never plaintext <masterKey>.
        var xmlEntries = sharedStore.ReadAllXmlElements();
        Assert.NotEmpty(xmlEntries);
        foreach (var xml in xmlEntries)
        {
            Assert.Contains("encryptedKey", xml, StringComparison.Ordinal);
            Assert.DoesNotContain("<masterKey", xml, StringComparison.OrdinalIgnoreCase);
        }

        // Replica B (new container/pod sharing Redis store + Vault MasterKey) seamlessly decrypts Replica A's cookie.
        using (var replicaBBase = GatewayTestSecurity.CreateGatewayFactory(
                   backendDestination: "http://127.0.0.1:9/",
                   configureServices: services => services.AddSingleton<IGatewayDataProtectionStore>(sharedStore)))
        using (var replicaB = replicaBBase.WithWebHostBuilder(wb =>
                   wb.UseSetting("DataProtection:MasterKey", gatewayMasterKey)))
        {
            using var _ = replicaB.CreateClient();
            var dpB = Microsoft.AspNetCore.DataProtection.DataProtectionCommonExtensions.CreateProtector(
                replicaB.Services.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>(),
                "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware",
                GatewayAuthPolicies.AdminBffCookieScheme,
                "v2");
            Assert.Equal("encrypted-admin-bff-ticket", dpB.Unprotect(protectedCookiePayload));
        }

        // Replica with wrong MasterKey cannot unwrap the key ring.
        using (var wrongKeyBase = GatewayTestSecurity.CreateGatewayFactory(
                   backendDestination: "http://127.0.0.1:9/",
                   configureServices: services => services.AddSingleton<IGatewayDataProtectionStore>(sharedStore)))
        using (var wrongKeyReplica = wrongKeyBase.WithWebHostBuilder(wb =>
                   wb.UseSetting("DataProtection:MasterKey", "different-master-key-cannot-decrypt-gateway-ring!")))
        {
            using var unusedClient = wrongKeyReplica.CreateClient();
            var dpWrong = wrongKeyReplica.Services.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector(
                    "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware",
                    GatewayAuthPolicies.AdminBffCookieScheme,
                    "v2");
            Assert.ThrowsAny<CryptographicException>(() => { dpWrong.Unprotect(protectedCookiePayload); });
        }
    }

    private sealed class InMemoryGatewayDataProtectionStore : IGatewayDataProtectionStore
    {
        private readonly Dictionary<string, string> _entries = new(StringComparer.Ordinal);
        public IReadOnlyCollection<string> ReadAllXmlElements() => _entries.Values.ToArray();
        public void StoreXmlElement(string friendlyName, string xml) => _entries[friendlyName ?? Guid.NewGuid().ToString("N")] = xml;
    }

    [Fact]
    public async Task GatewayEmitsStructuredSecurityAuditLogsAndRestrictsAdminLoginAuditsRouteToAdmins()
    {
        var auditSink = new CapturingAuditLoggerProvider();
        await using var backend = WebApplication.CreateBuilder().Build();
        backend.MapGet("/login-audits", (HttpContext ctx) => Results.Ok(new
        {
            forwardedIp = ctx.Request.Headers["X-Forwarded-For"].ToString(),
            correlationId = ctx.Request.Headers["X-Correlation-ID"].ToString()
        }));
        backend.Urls.Add("http://127.0.0.1:0");
        await backend.StartAsync();
        var backendUrl = backend.Urls.Single();

        using var baseFactory = GatewayTestSecurity.CreateGatewayFactory(
            backendDestination: backendUrl,
            configureServices: services => services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(auditSink));
        using var factory = baseFactory.WithWebHostBuilder(wb =>
        {
            wb.UseSetting("RateLimiting:AdminAuthPermitLimit", "2");
        });

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        // 1. /auth/login challenge emits structured audit event with CorrelationId, and 3rd request hits 429 audit log.
        using (var challengeReq = new HttpRequestMessage(HttpMethod.Get, "/auth/login?returnUrl=%2Fadmins"))
        {
            challengeReq.Headers.TryAddWithoutValidation("X-Correlation-ID", "gw-audit-corr-1");
            Assert.Equal(HttpStatusCode.Redirect, (await client.SendAsync(challengeReq)).StatusCode);
        }
        Assert.Equal(HttpStatusCode.Redirect, (await client.GetAsync("/auth/login")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.GetAsync("/auth/login")).StatusCode);

        Assert.Contains(auditSink.Messages, m => m.Contains("initiated administrator OIDC PKCE challenge", StringComparison.Ordinal) && m.Contains("gw-audit-corr-1", StringComparison.Ordinal));
        Assert.Contains(auditSink.Messages, m => m.Contains("gateway rate-limit rejected request", StringComparison.Ordinal));

        // 2. /admin-identity/login-audits is protected by customers-admin: 401 anonymous, 403 customer JWT, 200 admin JWT!
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/admin-identity/login-audits")).StatusCode);

        using (var customerReq = new HttpRequestMessage(HttpMethod.Get, "/admin-identity/login-audits"))
        {
            customerReq.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer",
                GatewayTestSecurity.CreateCustomerToken(Guid.NewGuid(), "user"));
            Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(customerReq)).StatusCode);
        }

        using (var adminReq = new HttpRequestMessage(HttpMethod.Get, "/admin-identity/login-audits"))
        {
            adminReq.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer",
                GatewayTestSecurity.CreateAdminToken(Guid.NewGuid(), "admin"));
            adminReq.Headers.TryAddWithoutValidation("X-Correlation-ID", "gw-audit-corr-admin");
            var adminResp = await client.SendAsync(adminReq);
            Assert.Equal(HttpStatusCode.OK, adminResp.StatusCode);
            var payload = await adminResp.Content.ReadAsStringAsync();
            Assert.Contains("gw-audit-corr-admin", payload, StringComparison.Ordinal);
        }
    }

    private sealed class CapturingAuditLoggerProvider : Microsoft.Extensions.Logging.ILoggerProvider
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<string> _messages = new();
        public IReadOnlyCollection<string> Messages => _messages.ToArray();
        public Microsoft.Extensions.Logging.ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _messages);
        public void Dispose() { }

        private sealed class CapturingLogger(
            string category,
            System.Collections.Concurrent.ConcurrentQueue<string> sink) : Microsoft.Extensions.Logging.ILogger
        {
            public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
            public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;
            public void Log<TState>(
                Microsoft.Extensions.Logging.LogLevel logLevel,
                Microsoft.Extensions.Logging.EventId eventId,
                TState state,
                Exception exception,
                Func<TState, Exception, string> formatter)
            {
                if (string.Equals(category, "Davids.Security.Audit", StringComparison.Ordinal))
                {
                    sink.Enqueue(formatter(state, exception));
                }
            }

            private sealed class NullScope : IDisposable
            {
                public static readonly NullScope Instance = new();
                public void Dispose() { }
            }
        }
    }
}
