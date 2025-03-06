using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using UserService.DTOs;
using UserService.Models;
using UserService.Services.Interfaces;
using static UserService.Config.RolesAndClaimsHelper;

namespace UserService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]    
    [Authorize]
    public class UserController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly ITokenService _tokenService;
        public UserController(UserManager<User> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<User> signInManager,
            IConfiguration configuration,
            ITokenService tokenService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _tokenService = tokenService;
        }


        [Authorize]
        [HttpGet("check")]
        public async Task<IActionResult> GetCheck()
        {      
            return Ok();
        }

        // Endpoint for user registration
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterUserDto registerDto)
        {
            var user = new User
            {
                UserName = registerDto.Email,
                Email = registerDto.Email,
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                PhoneNumber = registerDto.PhoneNumber,
                DateOfBirth = registerDto.DateOfBirth,
                IsDeleted = false
            };

            var result = await _userManager.CreateAsync(user, registerDto.Password);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok(new { message = "User created successfully" });
        }

        // Endpoint for user login
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginUserDto loginDto)
        {
            // Generate JWT or set up authentication cookie here (optional)
            // Validate the input
            if (string.IsNullOrEmpty(loginDto.Email) || string.IsNullOrEmpty(loginDto.Password))
            {
                return BadRequest(new { message = "Email and password are required." });
            }

            // Find the user by email
            var user = await _userManager.FindByEmailAsync(loginDto.Email);
            if (user == null)
            {
                return Unauthorized(new { message = "Invalid login attempt." });
            }

            // Attempt to sign in the user
            var result = await _signInManager.PasswordSignInAsync(user, loginDto.Password, isPersistent: false, lockoutOnFailure: false);
            if (!result.Succeeded)
            {
                return Unauthorized(new { message = "Invalid login attempt." });
            }

            // Check the number of active tokens for the user
            var canAddNewLogin = await _tokenService.CanAddNewLogin(user.Id);
            if (canAddNewLogin) // Maximum allowed active tokens
            {
                return BadRequest(new { message = "Maximum number of active sessions reached. Please log out from another device." });
            }

            // Generate the JWT token
            var token = await GenerateJwtTokenAsync(user);

            // Store the token in Redis
            var expiry = TimeSpan.FromMinutes(Convert.ToInt32(_configuration["Jwt:ExpiryInMinutes"]));
            await _tokenService.StoreTokenAsync(user.Id, token, expiry);

            // Return the token and user information
            return Ok(new
            {
                Token = token,
                User = new
                {
                    Id = user.Id,
                    Email = user.Email,
                    UserName = user.UserName
                }
            });
        }


        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var token = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            await _tokenService.InvalidateTokenAsync(token);

            return Ok(new { message = "Logged out successfully." });
        }

        // Endpoint to get user profile
        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound(new { message = "User not found" });
            }

            var userProfile = new UserProfileDto
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                DateOfBirth = user.DateOfBirth,
                PhoneNumber = user.PhoneNumber,
                CreatedAt = user.CreatedAt,
                UpdatedAt = user.UpdatedAt
            };

            return Ok(userProfile);
        }



        [HttpPost("add-claims-roles")]
        //[Authorize(Roles = nameof(Roles.Admin))]
        public async Task<IActionResult> AddClaimsAndRoles([FromBody] AddClaimsAndRolesDto model)
        {
            // Validate the input
            if (model == null || string.IsNullOrEmpty(model.UserId))
            {
                return BadRequest("User ID is required.");
            }

            // Find the user by ID
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            // Add roles to the user
            if (model.Roles != null && model.Roles.Any())
            {
                foreach (var role in model.Roles)
                {
                    // Check if the role exists
                    if (!await _roleManager.RoleExistsAsync(role))
                    {
                        return BadRequest($"Role '{role}' does not exist.");
                    }

                    // Add the role to the user
                    var result = await _userManager.AddToRoleAsync(user, role);
                    if (!result.Succeeded)
                    {
                        return BadRequest($"Failed to add role '{role}' to the user.");
                    }
                }
            }

            // Add claims to the user
            if (model.Claims != null && model.Claims.Any())
            {
                foreach (var claim in model.Claims)
                {
                    // Add the claim to the user
                    var result = await _userManager.AddClaimAsync(user, new Claim(claim.Type, claim.Value));
                    if (!result.Succeeded)
                    {
                        return BadRequest($"Failed to add claim '{claim.Type}: {claim.Value}' to the user.");
                    }
                }
            }

            // Optionally, check if the user meets a specific policy
            //var authorizationService = HttpContext.RequestServices.GetRequiredService<IAuthorizationService>();
            //var policyCheck = await authorizationService.AuthorizeAsync(User, "CanRead");
            //if (!policyCheck.Succeeded)
            //{
            //    return BadRequest("User does not meet the 'CanRead' policy requirements.");
            //}

            return Ok(new { message = "Claims, roles, and policies applied successfully." });
        }

        [HttpPost("changepassword")]
        public async Task<IActionResult> UpdatePassword(Guid userId, string email, string newPassword)
        {
            // Get the user by ID
            var user = await _userManager.FindByIdAsync(userId.ToString());

            // If user not found, handle the error
            if (user == null)
            {
                return NotFound($"User with ID {userId} not found.");
            }

            // Verify the provided email matches the user's email
            if (user.Email != email)
            {
                return BadRequest("Email does not match the user.");
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Update the user's password
            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);

            if (!result.Succeeded)
            {
                // Handle password update errors (e.g., invalid password format)
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return BadRequest(ModelState);
            }

            // Password updated successfully
            return Ok("Password updated successfully.");
        }

        private async Task<string> GenerateJwtTokenAsync(User user)
        {
            // Get JWT settings from configuration
            var jwtKey = _configuration["Jwt:Key"];
            var jwtIssuer = _configuration["Jwt:Issuer"];
            var jwtAudience = _configuration["Jwt:Audience"];
            var jwtExpiryInMinutes = Convert.ToInt32(_configuration["Jwt:ExpiryInMinutes"]);

            // Create claims for the token
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // Unique token ID
            };

            // Add user roles to claims (if applicable)
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            // Add user-specific claims
            var userClaims = await _userManager.GetClaimsAsync(user);
            if (userClaims.Any())
                claims.AddRange(userClaims);

            // Create the signing key
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Create the token
            var token = new JwtSecurityToken(
                issuer: jwtIssuer,
                audience: jwtAudience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(jwtExpiryInMinutes),
                signingCredentials: creds
            );

            // Serialize the token to a string
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}