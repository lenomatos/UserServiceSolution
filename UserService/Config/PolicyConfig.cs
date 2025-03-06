using static UserService.Config.RolesAndClaimsHelper;

namespace UserService.Config
{
    public static class PolicyConfig
    {
        public static void AddAuthorizationAndPolicyConfig(this WebApplicationBuilder builder)
        {
            // Define policies
            builder.Services.AddAuthorization(options =>
            {
                // Policy based on a role
                options.AddPolicy(GetRoleOrClaimOrPolice(Policies.AdminOnly), policy =>
                    policy.RequireRole(GetRoleOrClaimOrPolice(Roles.Admin))
                );

                // Policy based on a role
                options.AddPolicy(GetRoleOrClaimOrPolice(Policies.SellerOnly), policy =>
                    policy.RequireRole(GetRoleOrClaimOrPolice(Roles.Seller))
                );

                // Policy based on a claim
                options.AddPolicy(GetRoleOrClaimOrPolice(Policies.CanUpdate), policy =>
                {
                    policy.RequireClaim(GetRoleOrClaimOrPolice(Claims.Write));
                    policy.RequireClaim(GetRoleOrClaimOrPolice(Claims.Delete));
                });

                // Policy based on a claim and a role
                options.AddPolicy(GetRoleOrClaimOrPolice(Policies.IsVerifiedCustomer), policy =>
                {
                    policy.RequireClaim(GetRoleOrClaimOrPolice(Claims.IsVerified));
                    policy.RequireRole(GetRoleOrClaimOrPolice(Roles.Customer));
                });
            });
        }
    }
}