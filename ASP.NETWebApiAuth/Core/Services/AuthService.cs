using ASP.NETWebApiAuth.Core.Dtos;
using ASP.NETWebApiAuth.Core.Entities;
using ASP.NETWebApiAuth.Core.Interfaces;
using ASP.NETWebApiAuth.Core.OtherObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ASP.NETWebApiAuth.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);

            if (user == null)
            {
                return new AuthServiceResponseDto()
                {
                    Successful = false,
                    Message = "Invalid credentials"
                };
            }

            bool isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!isPasswordCorrect)
            {
                return new AuthServiceResponseDto()
                {
                    Successful = false,
                    Message = "Invalid credentials"
                };
            }

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString()),
            };

            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var token = GenerateNewJsonWebToken(authClaims);

            return new AuthServiceResponseDto()
            {
                Successful = true,
                Message = token
            };
        }

        public async Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePremissionDto updatePremissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePremissionDto.UserName);

            if (user == null)
            {
                return new AuthServiceResponseDto()
                {
                    Successful = false,
                    Message = "Invalid username"
                };
            }

            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);

            return new AuthServiceResponseDto()
            {
                Successful = true,
                Message = "Admin role successfuly added"
            };
        }

        public async Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePremissionDto updatePremissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePremissionDto.UserName);

            if (user == null)
            {
                return new AuthServiceResponseDto()
                {
                    Successful = false,
                    Message = "Invalid username"
                };
            }

            await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);

            return new AuthServiceResponseDto()
            {
                Successful = true,
                Message = "Owner role successfuly added"
            };
        }

        public async Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto)
        {
            var isUserExists = await _userManager.FindByNameAsync(registerDto.UserName);

            if (isUserExists != null)
            {
                return new AuthServiceResponseDto()
                {
                    Successful = false,
                    Message = "User with the given Username already exists"
                };
            }

            ApplicationUser user = new ApplicationUser()
            {
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                UserName = registerDto.UserName,
                Email = registerDto.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var createUserResult = await _userManager.CreateAsync(user, registerDto.Password);

            if (!createUserResult.Succeeded)
            {
                StringBuilder errorMessage = new StringBuilder("User creation failed:\n");
                foreach (var error in createUserResult.Errors)
                {
                    errorMessage.AppendLine(error.Description);
                }

                return new AuthServiceResponseDto()
                {
                    Successful = false,
                    Message = errorMessage.ToString()
                };
            }

            // Default role is USER
            await _userManager.AddToRoleAsync(user, StaticUserRoles.USER);

            return new AuthServiceResponseDto()
            {
                Successful = true,
                Message = "User created successfully"
            };
        }

        public async Task<AuthServiceResponseDto> SeedRolesAsync()
        {
            bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
            {
                return new AuthServiceResponseDto()
                {
                    Successful = true,
                    Message = "Role seeding already done"
                };
            }

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));

            return new AuthServiceResponseDto()
            {
                Successful = true,
                Message = "Role seeding completed successfully"
            };
        }

        private string GenerateNewJsonWebToken(List<Claim> authClaims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var tokenObject = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
            );

            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

            return token;
        }
    }
}
