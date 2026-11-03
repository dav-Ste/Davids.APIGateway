using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Davids.APIGateway.Infrastructure.Auth;

public sealed class AdminOnlyRequirement : IAuthorizationRequirement;

public sealed class WorkforceReadRequirement : IAuthorizationRequirement;

public sealed class WorkforceMutateRequirement : IAuthorizationRequirement;

public sealed class CustomerOnlyRequirement : IAuthorizationRequirement;

public sealed class ResourceOwnerOrAdminRequirement : IAuthorizationRequirement;

public static class GatewayIdentityPredicates
{
    public static bool IsWorkforceRole(string? role)
        => string.Equals(role, "admin", StringComparison.Ordinal) ||
           string.Equals(role, "support", StringComparison.Ordinal) ||
           string.Equals(role, "auditor", StringComparison.Ordinal);

    public static bool CanMutateWorkforceRole(string? role)
        => string.Equals(role, "admin", StringComparison.Ordinal) ||
           string.Equals(role, "support", StringComparison.Ordinal);

    private static bool IsWorkforceAuthenticationType(string? authenticationType)
        => string.Equals(authenticationType, GatewayAuthPolicies.AdminBearerScheme, StringComparison.Ordinal) ||
           string.Equals(authenticationType, GatewayAuthPolicies.AdminBffCookieScheme, StringComparison.Ordinal);

    public static bool IsCustomerAuthenticationType(string? authenticationType)
        => string.Equals(authenticationType, GatewayAuthPolicies.CustomerBearerScheme, StringComparison.Ordinal) ||
           string.Equals(authenticationType, GatewayAuthPolicies.CustomerBffCookieScheme, StringComparison.Ordinal);

    public static bool IsVerifiedCustomer(ClaimsPrincipal user)
        => user.Identities.Any(identity =>
            identity.IsAuthenticated &&
            IsCustomerAuthenticationType(identity.AuthenticationType) &&
            identity.HasClaim("role", "user"));

    public static ClaimsIdentity? FindVerifiedCustomerIdentity(ClaimsPrincipal user)
        => user.Identities.FirstOrDefault(identity =>
            identity.IsAuthenticated &&
            IsCustomerAuthenticationType(identity.AuthenticationType) &&
            identity.HasClaim("role", "user"));

    public static bool IsVerifiedAdmin(ClaimsPrincipal user)
        => user.Identities.Any(identity =>
            identity.IsAuthenticated &&
            IsWorkforceAuthenticationType(identity.AuthenticationType) &&
            identity.HasClaim("role", "admin"));

    public static bool IsVerifiedWorkforceReader(ClaimsPrincipal user)
        => user.Identities.Any(identity =>
            identity.IsAuthenticated &&
            IsWorkforceAuthenticationType(identity.AuthenticationType) &&
            IsWorkforceRole(identity.FindFirst("role")?.Value));

    public static bool IsVerifiedWorkforceMutator(ClaimsPrincipal user)
        => user.Identities.Any(identity =>
            identity.IsAuthenticated &&
            IsWorkforceAuthenticationType(identity.AuthenticationType) &&
            CanMutateWorkforceRole(identity.FindFirst("role")?.Value));
}

public sealed class AdminOnlyAuthorizationHandler : AuthorizationHandler<AdminOnlyRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AdminOnlyRequirement requirement)
    {
        if (GatewayIdentityPredicates.IsVerifiedAdmin(context.User))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

public sealed class WorkforceReadAuthorizationHandler : AuthorizationHandler<WorkforceReadRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        WorkforceReadRequirement requirement)
    {
        if (GatewayIdentityPredicates.IsVerifiedWorkforceReader(context.User))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

public sealed class WorkforceMutateAuthorizationHandler : AuthorizationHandler<WorkforceMutateRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        WorkforceMutateRequirement requirement)
    {
        if (GatewayIdentityPredicates.IsVerifiedWorkforceMutator(context.User))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

public sealed class CustomerOnlyAuthorizationHandler : AuthorizationHandler<CustomerOnlyRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        CustomerOnlyRequirement requirement)
    {
        if (GatewayIdentityPredicates.IsVerifiedCustomer(context.User))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

public sealed class ResourceOwnerOrAdminHandler : AuthorizationHandler<ResourceOwnerOrAdminRequirement>
{
    private static readonly string[] RouteOwnerKeys = ["userId", "customerId"];

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ResourceOwnerOrAdminRequirement requirement)
    {
        var isWorkforce = GatewayIdentityPredicates.IsVerifiedWorkforceReader(context.User);

        var httpContext = context.Resource switch
        {
            HttpContext direct => direct,
            IHttpContextAccessor accessor => accessor.HttpContext,
            _ => null
        };

        // Customer Identity (/identity/users/{userId}) is strictly customer-owned; employees use /customer-accounts/*.
        if (isWorkforce && (httpContext is null || !httpContext.Request.Path.StartsWithSegments("/identity")))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        if (httpContext is null)
        {
            return Task.CompletedTask;
        }

        var customerIdentity = GatewayIdentityPredicates.FindVerifiedCustomerIdentity(context.User);
        var subjectClaim = customerIdentity?.FindFirst("sub")?.Value;
        if (!Guid.TryParse(subjectClaim, out var subjectId) || subjectId == Guid.Empty)
        {
            return Task.CompletedTask;
        }

        foreach (var key in RouteOwnerKeys)
        {
            var rawValue = httpContext.GetRouteValue(key)?.ToString();
            if (string.IsNullOrWhiteSpace(rawValue))
            {
                continue;
            }

            if (Guid.TryParse(rawValue, out var targetId) && targetId == subjectId)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }

        return Task.CompletedTask;
    }
}
