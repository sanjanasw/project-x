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

        [Authorize(Roles = "Admin")]
        [HttpGet("{role}")]
        public async Task<IActionResult> GetUsers([FromRoute] UserRoles role)
        {
            return Ok(await _userService.GetUsers(role));
        }

        [Authorize]
        [HttpGet("CurrentUser")]
        public async Task<IActionResult> GetCurrentUser()
        {
            return Ok(await _authService.GetCurrentLoggedInUserAsync());
        }

        [AllowAnonymous]
        [HttpPost("CreateUser")]
        public async Task<IActionResult> CreateUser(RegisterViewModel model)
        {
            return Ok(await _authService.CreateUserAsync(model, UserRoles.User));
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("CreateAdmin")]
        public async Task<IActionResult> CreateAdmin(RegisterViewModel model)
        {
            return Ok(await _authService.CreateUserAsync(model, UserRoles.Admin));
        }
    }
}

