# Davids API Gateway

The .NET 10 API Gateway is the browser-facing YARP edge and **OpenID Connect Backend-for-Frontend (BFF)** for `Davids.Services.Identity` (customer OIDC authority), `Davids.Services.AdminIdentity` (administrator OIDC authority), `Davids.Services.Customers`, and `Davids.Frontend.Admin` (the Admin Web frontend).

It enforces dual-authority **RS256** OIDC JWT validation via public JWKS discovery (**zero signing keys stored on the gateway**), runs a confidential **OAuth 2.1 Authorization Code + PKCE (`S256`)** BFF session (`AdminBffCookie` / `davids_admin_bff`) for `Davids.Frontend.Admin`, enforces CSRF checks (`X-Requested-With: DavidsAdmin` + same-origin `Origin`) on cookie-authenticated mutations, strips incoming `Cookie` and spoofed `X-Auth-*` headers, injects verified `Authorization: Bearer` + `X-Auth-*` headers downstream, and propagates correlation IDs and W3C distributed trace context.

## Projects

- `src/Davids.APIGateway.Api`: YARP host, Vault KV-v2 startup loader (`secret/data/davids/gateway`), OIDC BFF endpoints (`/auth/login`, `/auth/session`, `/auth/logout`), gateway request-context middleware, CSP/security headers, and `/health` & `/gateway-info`.
- `src/Davids.APIGateway.Infrastructure`: Dual-authority RS256 JWKS bearer authentication (`CustomerBearer` + `AdminBearer`), `AddOpenIdConnect` PKCE BFF (`AdminOidc` + `AdminBffCookie` with automatic server-side refresh rotation and Redis/RFC 7009 revocation), `GatewayAuthorizationResultHandler`, `ResourceOwnerOrAdminHandler`, YARP transforms, and destination validation.
- `tests/Davids.APIGateway.Tests`: 34 end-to-end tests covering OIDC PKCE BFF login/callback/refresh/logout, CSRF protection, RS256 JWKS validation, admin frontend gating (`302 /login` vs `401` vs `403`), route isolation, anti-spoofing transforms, Redis revocation, security metrics, and W3C tracing.
- `Davids.ServiceDefaults`: shared logging, health, OpenTelemetry, and service-discovery defaults from the sibling `Davids.Shared` repository.

```powershell
dotnet restore Davids.APIGateway.sln --locked-mode
dotnet build Davids.APIGateway.sln --no-restore -c Release
dotnet test Davids.APIGateway.sln --no-restore -c Release
```

## Self-Hosted OIDC Authentication & Admin BFF Architecture

Customer accounts (`identitydb`) and administrator accounts (`adminidentitydb`) are isolated across separate SQL databases, separate OpenIddict OIDC authorities, separate Vault KV paths, and distinct 2048-bit+ RSA signing keys:

- **`CustomerBearer`** (`CustomerOidc`): validates RS256 tokens via `Davids.Services.Identity`'s `/.well-known/openid-configuration` & `/.well-known/jwks` (`Audience: davids-services`), restricted strictly to `role == "user"`.
- **`AdminBearer`** (`AdminOidc`): validates RS256 tokens via `Davids.Services.AdminIdentity`'s `/.well-known/openid-configuration` & `/.well-known/jwks` (`Audience: davids-admin`), restricted strictly to `role == "admin"`.
- **`AdminBffCookie` (`davids_admin_bff`)**: encrypted ASP.NET Core `HttpOnly; SameSite=Lax` BFF session cookie backed by confidential OIDC client `davids-admin-bff` (`secret/data/davids/gateway` -> `AdminOidc:BffClientSecret`) using `Authorization Code + PKCE (S256)`. Raw access and refresh tokens remain encrypted server-side, are refreshed transparently via `/connect/token` prior to expiry, and are injected as `Authorization: Bearer <access_token>` only on internal YARP hops to `admin-identity` and `customers`.

Only verified administrators (`AdminBearer` or `AdminBffCookie`) can access `Davids.Frontend.Admin` (`/` and workspace assets):

- Unauthenticated browser HTML navigations (`Accept: text/html`) to `/` redirect (`302 Found`, `Cache-Control: no-store`) to `/login`.
- Unauthenticated asset/API requests return `401 Unauthorized`.
- Authenticated customer users (`CustomerBearer`) receive `403 Forbidden` on `Davids.Frontend.Admin` and all admin endpoints.

| Route / endpoint | Methods | Gateway policy | Purpose |
|---|---|---|---|
| `/health`, `/alive`, `/gateway-info` | `GET` | `AllowAnonymous` | Gateway probes and metadata |
| `/auth/login`, `/signin-oidc` | `GET` | `AllowAnonymous` | OIDC Authorization Code + PKCE challenge & callback |
| `/auth/session` | `GET` | `AllowAnonymous` | Non-sensitive BFF session status (`authenticated`, `sub`, `email`, `role`, `expiresAt`) |
| `/auth/logout` | `POST` | `AllowAnonymous` (CSRF-verified) | Clears `davids_admin_bff` cookie and revokes access + refresh tokens via RFC 7009 |
| `/login`, `/login.css`, `/login.js`, `/favicon.svg` | `GET`, `HEAD` | `Anonymous` | Minimal public administrator SSO entry page |
| `/{**remainder}` (`admin-web-frontend`) | `GET`, `HEAD` | `admin-frontend` | Protected `Davids.Frontend.Admin` workspace (admin only) |
| `/admin-identity/.well-known/{**remainder}` | `GET`, `HEAD` | `Anonymous` | Admin OIDC discovery and public RSA JWKS |
| `/admin-identity/connect/authorize`, `authorize.css`, `token`, `revocation`, `logout` | `GET`, `POST` | `Anonymous` | Admin OIDC protocol endpoints (`PathRemovePrefix: /admin-identity`) |
| `/admin-identity/connect/userinfo` | `GET`, `POST` | `customers-admin` | Authenticated Admin OIDC UserInfo |
| `/admin-identity/{**remainder}` | Any | `customers-admin` | `/admin-identity/me`, `GET/POST /admin-identity/users` (no public `/sign-up`) |
| `/identity/.well-known/{**remainder}` | `GET`, `HEAD` | `Anonymous` | Customer OIDC discovery and public RSA JWKS |
| `/identity/connect/authorize`, `authorize.css`, `token`, `revocation`, `logout` | `GET`, `POST` | `Anonymous` | Customer OIDC protocol endpoints (`PathRemovePrefix: /identity`) |
| `/identity/connect/userinfo` | `GET`, `POST` | `customer-authenticated` | Authenticated Customer OIDC UserInfo |
| `/identity/sign-up` | `POST` | `Anonymous` | Public customer registration |
| `/identity/users/{userId}` | `GET` | `resource-owner-or-admin` | Matching customer `sub` GUID |
| `/identity/{**remainder}` | Any | `customer-authenticated` | `/identity/me` and remaining Customer Identity routes |
| `/customers` (`?search=&state=&vip=`) | `GET` | `customers-admin` | Administrator customer directory search & filter |
| `/customers/{customerId}` | `PUT` | `customers-admin` | Administrator customer profile & state editing |
| `/customers/{customerId}/state/{state}` | `PUT` | `customers-admin` | Administrator customer state transitions |
| `/customers/{customerId}`, `/customers/{customerId}/state` | `GET` | `resource-owner-or-admin` | Matching customer `sub` GUID or verified administrator |
| `/customers/{**remainder}` | Any | `authenticated` | `POST /customers` and remaining Customers routes |
