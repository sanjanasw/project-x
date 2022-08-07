using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Project_X.Business.Interfaces;
using Project_X.Business.ViewModels;
using Project_X.Common.Enums;

namespace Project_X.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/[controller]")]
    public class UsersController : Controller
    {
        private readonly IAuthService _authService;
        private readonly IUserService _userService;

        public UsersController(IAuthService authService, IUserService userService) =>
            (_authService, _userService) = (authService, userService);

        [HttpGet("{role}")]
        public async Task<IActionResult> GetUsers([FromRoute] UserRoles role)
        {
            return Ok(await _userService.GetUsers(role));
        }

        [AllowAnonymous]
        [HttpPost("CreateUser")]
        public async Task<IActionResult> CreateUser(RegisterViewModel model)
        {
            var result = await _authService.CreateUserAsync(model, UserRoles.User);
            return Ok(result);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("CreateAdmin")]
        public async Task<IActionResult> CreateAdmin(RegisterViewModel model)
        {
            var result = await _authService.CreateUserAsync(model, UserRoles.Admin);
            return Ok(result);
        }
    }
}

