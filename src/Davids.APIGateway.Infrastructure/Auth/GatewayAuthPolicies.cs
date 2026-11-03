namespace Davids.APIGateway.Infrastructure.Auth;

public static class GatewayAuthPolicies
{
    public const string CustomerBearerScheme = "CustomerBearer";
    public const string CustomerBffCookieScheme = "CustomerBffCookie";
    public const string CustomerOidcScheme = "CustomerOidc";
    public const string AdminBearerScheme = "AdminBearer";
    public const string AdminBffCookieScheme = "AdminBffCookie";
    public const string AdminOidcScheme = "AdminOidc";

    public const string Authenticated = "authenticated";
    public const string CustomerAuthenticated = "customer-authenticated";
    public const string CustomerFrontend = "customer-frontend";
    public const string CustomersAdmin = "customers-admin";
    public const string WorkforceRead = "workforce-read";
    public const string WorkforceMutate = "workforce-mutate";
    public const string WorkforceSelfMutate = "workforce-self-mutate";
    public const string AdminFrontend = "admin-frontend";
    public const string ResourceOwnerOrAdmin = "resource-owner-or-admin";

    public const string AdminBffCookieName = "davids_admin_bff";
    public const string AdminOidcCorrelationCookiePrefix = "davids_oidc_corr.";
    public const string AdminOidcNonceCookiePrefix = "davids_oidc_nonce.";

    public const string CustomerBffCookieName = "davids_customer_bff";
    public const string CustomerOidcCorrelationCookiePrefix = "davids_cust_oidc_corr.";
    public const string CustomerOidcNonceCookiePrefix = "davids_cust_oidc_nonce.";

    public const string AdminCsrfHeaderName = "X-Requested-With";
    public const string AdminCsrfHeaderValue = "DavidsAdmin";
    public const string CustomerCsrfHeaderValue = "DavidsWeb";

    public const string VerifiedAdminRawTokenItemKey = "Davids.VerifiedAdminRawToken";
    public const string VerifiedAdminTokenIdItemKey = "Davids.VerifiedAdminTokenId";
    public const string VerifiedCustomerRawTokenItemKey = "Davids.VerifiedCustomerRawToken";
    public const string VerifiedCustomerTokenIdItemKey = "Davids.VerifiedCustomerTokenId";

    public const string CsrfRejectedItemKey = "Davids.CsrfRejected";
    public const string CustomerCsrfRejectedItemKey = "Davids.CustomerCsrfRejected";

    public const string BackchannelHttpClientName = "AdminOidcBackchannel";
    public const string CustomerBackchannelHttpClientName = "CustomerOidcBackchannel";

    public const string GatewayAdminAuthRateLimitPolicy = "gateway-admin-auth";
    public const string GatewayCustomerAuthRateLimitPolicy = "gateway-customer-auth";
    public const string GatewayApiRateLimitPolicy = "gateway-api";
}
