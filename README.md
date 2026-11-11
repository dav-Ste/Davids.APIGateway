# Davids.APIGateway

| Pull Request CI | CodeQL SAST | Platform Architecture & Orchestration |
|---|---|---|
| [![CI — Build, Tests & Security](https://github.com/dav-Ste/Davids.APIGateway/actions/workflows/pull-request-ci.yml/badge.svg?branch=main)](https://github.com/dav-Ste/Davids.APIGateway/actions/workflows/pull-request-ci.yml) | [![CodeQL — PR, Main & Weekly SAST](https://github.com/dav-Ste/Davids.APIGateway/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/dav-Ste/Davids.APIGateway/actions/workflows/codeql.yml) | [**`Davids` — Architecture & Security Diagram**](https://github.com/dav-Ste/Davids#architecture-project-relationships--security-posture) |

`Davids.APIGateway` (`Davids.APIGateway.slnx`, default local port `:17320`) is the browser-facing `.NET 10` **YARP `2.3.0` edge reverse proxy** and confidential **OpenID Connect Backend-for-Frontend (BFF)** for [`Davids.Services.Identity`](https://github.com/dav-Ste/Davids.Services.Identity) (customer OIDC authority), [`Davids.Services.AdminIdentity`](https://github.com/dav-Ste/Davids.Services.AdminIdentity) (administrator OIDC authority), [`Davids.Services.Customers`](https://github.com/dav-Ste/Davids.Services.Customers), and [`Davids.Frontend.Admin`](https://github.com/dav-Ste/Davids.Frontend.Admin) (the Admin Web frontend).

It enforces dual-authority **RS256** OIDC JWT validation via public JWKS discovery (**zero signing keys stored on the gateway**), runs a confidential **OAuth 2.1 Authorization Code + PKCE (`S256`)** BFF session (`AdminBffCookie` / `davids_admin_bff`) for `Davids.Frontend.Admin`, enforces CSRF checks (`X-Requested-With: DavidsAdmin` + same-origin `Origin`) on cookie-authenticated mutations, checks Redis for RFC 7009 revoked token `jti`s, strips incoming `Cookie` and spoofed `X-Auth-*` headers, injects verified `Authorization: Bearer` + `X-Auth-*` headers downstream, enforces sliding-window rate limits, and propagates correlation IDs and W3C distributed trace context directly to backend services (with Istio enforcing `STRICT` mTLS in-cluster).

## Projects

- `src/Davids.APIGateway.Api`: YARP host, Vault KV-v2 startup loader (`secret/data/davids/gateway`), OIDC BFF endpoints (`/auth/login`, `/auth/session`, `/auth/logout`), gateway request-context middleware, CSP/security headers, and `/health`, `/alive`, & `/gateway-info`.
- `src/Davids.APIGateway.Infrastructure`: Dual-authority `RS256` JWKS bearer authentication (`CustomerBearer` + `AdminBearer`), `AddOpenIdConnect` PKCE BFF (`AdminOidc` + `AdminBffCookie` with automatic server-side refresh rotation and Redis/RFC 7009 revocation), `GatewayAuthorizationResultHandler`, `ResourceOwnerOrAdminHandler`, YARP transforms, and destination validation.
- `tests/Davids.APIGateway.Tests`: unit, architecture, and integration tests covering OIDC PKCE BFF login/callback/refresh/logout, CSRF protection, `RS256` JWKS validation, admin frontend gating (`302 /admin/login` vs `401` vs `403`), route isolation, anti-spoofing transforms, Redis revocation, security metrics, and W3C tracing.

## Self-Hosted OIDC authentication & Admin BFF architecture

Customer accounts (`identitydb`) and administrator accounts (`adminidentitydb`) are isolated across separate SQL databases, separate OpenIddict OIDC authorities, separate Vault KV paths, and distinct 2048-bit+ RSA signing keys:

- **`CustomerBearer`** (`CustomerOidc`): Validates `RS256` tokens via `Davids.Services.Identity`'s `/.well-known/openid-configuration` & `/.well-known/jwks` (`Audience: davids-services`), restricted strictly to `role == "user"`.
- **`AdminBearer`** (`AdminOidc`): Validates `RS256` tokens via `Davids.Services.AdminIdentity`'s `/.well-known/openid-configuration` & `/.well-known/jwks` (`Audience: davids-admin`), restricted to workforce roles `admin`, `support`, and `auditor`.
- **`AdminBffCookie` (`davids_admin_bff`)**: Encrypted ASP.NET Core `HttpOnly; SameSite=Lax` BFF session cookie backed by confidential OIDC client `davids-admin-bff` (`secret/data/davids/gateway` -> `AdminOidc:BffClientSecret`) using `Authorization Code + PKCE (S256)`. Raw access and refresh tokens remain encrypted server-side, are refreshed transparently via `/connect/token` prior to expiry, and are injected as `Authorization: Bearer <access_token>` only on internal YARP hops to `admin-identity` and `customers`.

Only verified workforce users (`admin`, `support`, or `auditor`, via `AdminBearer` or `AdminBffCookie`) can access `Davids.Frontend.Admin` (`/admin` and workspace assets):

- Unauthenticated browser HTML navigations (`Accept: text/html`) to `/admin` redirect (`302 Found`, `Cache-Control: no-store`) to `/admin/login`. Customer portal navigations to `/` redirect to `/login`.
- Unauthenticated asset/API requests return `401 Unauthorized`.
- Customer-only sessions are redirected to the workforce sign-in page for HTML navigation; customer requests for protected admin assets or APIs receive `403 Forbidden`.

## Gateway route & policy matrix

| Route / endpoint | Methods | Gateway policy | Purpose |
|---|---|---|---|
| `/health`, `/alive`, `/gateway-info` | `GET` | `AllowAnonymous` | Gateway probes and metadata |
| `/auth/login`, `/signin-oidc` | `GET` | `AllowAnonymous` | OIDC Authorization Code + PKCE challenge & callback |
| `/auth/session` | `GET` | `AllowAnonymous` | Non-sensitive BFF session status (`authenticated`, `sub`, `email`, `role`, `expiresAt`) |
| `/auth/logout` | `POST` | `AllowAnonymous` (CSRF-verified) | Clears `davids_admin_bff` cookie and revokes access + refresh tokens via RFC 7009 |
| `/login`, `/login.css`, `/login.js`, `/favicon.svg` | `GET`, `HEAD` | `Anonymous` | Customer SSO entry page |
| `/admin/login`, `/admin/login.css`, `/admin/login.js`, `/admin/favicon.svg` | `GET`, `HEAD` | `Anonymous` | Workforce SSO entry page |
| `/admin`, `/admin/{**remainder}` | `GET`, `HEAD` | `admin-frontend` | Protected workforce portal; gateway removes `/admin` upstream |
| `/{**remainder}` | `GET`, `HEAD` | `customer-frontend` | Protected customer portal; API routes take precedence |
| `/admin-identity/.well-known/{**remainder}` | `GET`, `HEAD` | `Anonymous` | Admin OIDC discovery and public RSA JWKS |
| `/admin-identity/connect/authorize`, `authorize.css`, `token`, `revocation`, `logout` | `GET`, `POST` | `Anonymous` | Admin OIDC protocol endpoints (`PathRemovePrefix: /admin-identity`) |
| `/admin-identity/connect/userinfo` | `GET`, `POST` | `customers-admin` | Authenticated Admin OIDC UserInfo |
| `/admin-identity/{**remainder}` | Any | `customers-admin` | `/admin-identity/me`, `GET/POST /admin-identity/users`, `GET /admin-identity/login-audits` (no public `/sign-up`) |
| `/identity/.well-known/{**remainder}` | `GET`, `HEAD` | `Anonymous` | Customer OIDC discovery and public RSA JWKS |
| `/identity/connect/authorize`, `authorize.css`, `token`, `revocation`, `logout` | `GET`, `POST` | `Anonymous` | Customer OIDC protocol endpoints (`PathRemovePrefix: /identity`) |
| `/identity/connect/userinfo` | `GET`, `POST` | `customer-authenticated` | Authenticated Customer OIDC UserInfo |
| `/identity/sign-up` | `POST` | `Anonymous` | Public customer registration |
| `/identity/users/{userId}` | `GET` | `resource-owner-or-admin` | Matching customer `sub` GUID |
| `/identity/{**remainder}` | Any | `customer-authenticated` | `/identity/me`, `/identity/me/login-audits`, and remaining Customer Identity routes |
| `/customers` (`?search=&state=&vip=`) | `GET` | `customers-admin` | Administrator customer directory search & filter |
| `/customers/{customerId}` | `PUT` | `customers-admin` | Administrator customer profile & state editing |
| `/customers/{customerId}/state/{state}` | `PUT` | `customers-admin` | Administrator customer state transitions |
| `/customers/{customerId}`, `/customers/{customerId}/state` | `GET` | `resource-owner-or-admin` | Matching customer `sub` GUID or verified administrator |
| `/customers/{**remainder}` | Any | `authenticated` | `POST /customers` and remaining Customers routes |

## Build, test & container image

Clone [`Davids.Shared`](https://github.com/dav-Ste/Davids.Shared) (`../Davids.Shared`) alongside `Davids.APIGateway` (or pass `/p:UseSharedPackageReference=true` to consume `Davids.ServiceDefaults` as a NuGet package without cloning `Davids.Shared`):

```powershell
dotnet restore Davids.APIGateway.slnx --locked-mode
dotnet build Davids.APIGateway.slnx --no-restore -c Release -warnaserror
dotnet test Davids.APIGateway.slnx --no-build --no-restore -c Release
```

Build the hardened multi-stage container image (`USER 10001:10001`, `EXPOSE 8080`) from the parent workspace directory:

```powershell
docker build -f Davids.APIGateway/Dockerfile -t davids-api-gateway:local ..
```

## Related repositories

- [`Davids`](https://github.com/dav-Ste/Davids) — `.NET 10` Aspire AppHost, Vault bootstrap, Kubernetes/Istio manifests, architecture diagram & lifecycle security suite
- [`Davids.Shared`](https://github.com/dav-Ste/Davids.Shared) — `Davids.ServiceDefaults` shared observability, Data Protection, and resilience defaults
- [`Davids.Services.Identity`](https://github.com/dav-Ste/Davids.Services.Identity) — Customer OpenIddict `RS256` OIDC Provider (`identitydb`)
- [`Davids.Services.AdminIdentity`](https://github.com/dav-Ste/Davids.Services.AdminIdentity) — Administrator OpenIddict `RS256` OIDC Provider (`adminidentitydb`)
- [`Davids.Services.Customers`](https://github.com/dav-Ste/Davids.Services.Customers) — Customer profiles & order tracking API (`customersdb`)
- [`Davids.Frontend.Admin`](https://github.com/dav-Ste/Davids.Frontend.Admin) — Passwordless Workforce RBAC customer, IAM & audit web UI (`AdminBffCookie` / `davids_admin_bff`)
- [`Davids.Frontend.Web`](https://github.com/dav-Ste/Davids.Frontend.Web) — Customer Self-Service Web Portal (`CustomerBffCookie` / `davids_customer_bff`, `/`, `/customer-auth/{login,session,logout}`)

The portal paths are on the **gateway origin**: customer `http://localhost:17320/` and workforce `http://localhost:17320/admin` (use HTTPS where configured). Direct frontend ports serve assets but do not provide gateway authentication or API routing.
