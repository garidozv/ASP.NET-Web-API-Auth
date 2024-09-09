using ASP.NETWebApiAuth.Core.Dtos;
using ASP.NETWebApiAuth.Core.Entities;
using ASP.NETWebApiAuth.Core.Interfaces;
using ASP.NETWebApiAuth.Core.OtherObjects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;


namespace ASP.NETWebApiAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var res = await _authService.SeedRolesAsync();

            return Ok(res.Message);
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var res = await _authService.RegisterAsync(registerDto);

            if (res.Successful)
            {
                return Ok(res.Message);
            }

            return BadRequest(res.Message);
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var res = await _authService.LoginAsync(loginDto);

            if (res.Successful)
            {
                return Ok(res.Message);
            }

            return Unauthorized(res.Message);
        }

        

        [HttpPost]
        [Route("make-admin")]
        [Authorize(Roles = StaticUserRoles.OWNER)]
        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePremissionDto updatePremissionDto)
        {
            var res = await _authService.MakeAdminAsync(updatePremissionDto);

            if (res.Successful)
            {
                return Ok(res.Message);
            }

            return BadRequest(res.Message);
        }

        [HttpPost]
        [Route("make-owner")]
        [Authorize(Roles = StaticUserRoles.OWNER)]
        public async Task<IActionResult> MakeOwner([FromBody] UpdatePremissionDto updatePremissionDto)
        {
            var res = await _authService.MakeOwnerAsync(updatePremissionDto);

            if (res.Successful)
            {
                return Ok(res.Message);
            }

            return BadRequest(res.Message);
        }
    }
}
