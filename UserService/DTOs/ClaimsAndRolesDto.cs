namespace UserService.DTOs
{
    public class AddClaimsAndRolesDto
    {
        public string UserId { get; set; } // ID of the user
        public List<string> Roles { get; set; } // List of roles to add
        public List<ClaimDto> Claims { get; set; } // List of claims to add
    }

    public class ClaimDto
    {
        public string Type { get; set; } // Claim type (e.g., "Permission")
        public string Value { get; set; } // Claim value (e.g., "Read")
    }
}
