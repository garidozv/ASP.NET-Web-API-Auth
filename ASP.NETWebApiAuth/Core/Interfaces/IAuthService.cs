using ASP.NETWebApiAuth.Core.Dtos;

namespace ASP.NETWebApiAuth.Core.Interfaces
{
    public interface IAuthService
    {
        Task<AuthServiceResponseDto> SeedRolesAsync();
        Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto);
        Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto);
        Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePremissionDto updatePremissionDto);
        Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePremissionDto updatePremissionDto);
    }
}
