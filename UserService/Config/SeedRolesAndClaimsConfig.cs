using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using UserService.Models;
using static UserService.Config.RolesAndClaimsHelper;

namespace UserService.Config
{
    public static class SeedRolesAndClaimsConfig
    {
        // Method to seed roles and claims
        public static async Task SeedRolesAndClaims(IServiceProvider services)
        {
            var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = services.GetRequiredService<UserManager<User>>();

            // Seed roles from the Roles enum
            foreach (var role in Enum.GetValues(typeof(Roles)))
            {
                var roleName = role.ToString();
                if (!await roleManager.RoleExistsAsync(roleName))
                {
                    await roleManager.CreateAsync(new IdentityRole(roleName));
                }
            }

            // Seed claims from the Claims enum
            foreach (var claim in Enum.GetValues(typeof(Claims)))
            {
                var claimValue = claim.ToString();
                var adminRole = await roleManager.FindByNameAsync(Roles.Admin.ToString());
                if (adminRole != null)
                {
                    var existingClaim = await roleManager.GetClaimsAsync(adminRole);
                    if (!existingClaim.Any(c => c.Type == "Permission" && c.Value == claimValue))
                    {
                        await roleManager.AddClaimAsync(adminRole, new Claim("Permission", claimValue));
                    }
                }
            }
         
        }
    }


    
}
