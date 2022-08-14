using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Project_X.Business.Interfaces;
using Project_X.Business.ViewModels;
using Project_X.Common.Enums;
using System.Net.Mime;

namespace Project_X.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/[controller]")]
    [Produces(MediaTypeNames.Application.Json)]
    [Consumes(MediaTypeNames.Application.Json)]
    public class UsersController : Controller
    {
        private readonly IAuthService _authService;
        private readonly IUserService _userService;

        public UsersController(IAuthService authService, IUserService userService) =>
            (_authService, _userService) = (authService, userService);

        [Authorize(Roles = "Admin")]
        [HttpGet]
        public async Task<IActionResult> GetUsers([FromQuery] string? id, [FromQuery] UserRoles? role)
        {
            return Ok(await _userService.GetUsersAsync(role, id));
        }

        [Authorize]
        [HttpGet("current-user")]
        public async Task<IActionResult> GetCurrentUser()
        {
            return Ok(await _authService.GetCurrentLoggedInUserAsync());
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> CreateUser(RegisterViewModel model)
        {
            return Ok(await _authService.CreateUserAsync(model));
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("create-admin")]
        public async Task<IActionResult> CreateAdmin(AdminInviteViewModel model)
        {
            return Ok(await _authService.CreateAdminAsync(model));
        }

        [Authorize]
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateUser([FromRoute] string id, UserUpdateViewModel model)
        {
            return Ok(await _userService.UpdateUserAsync(id, model));
        }

        [Authorize(Roles = "Admin")]
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser([FromRoute] string id)
        {
            var result = await _userService.UserDeleteAsync(id);

            if (result)
            {
                return Ok("User deleted successfully");
            }
            throw new Exception("user deletion unsuccessful");
        }

        [AllowAnonymous]
        [HttpPatch("update-email")]
        public async Task<IActionResult> UpdateEmail(UpdateEmailViewModel model)
        {
            var result = await _userService.UpdateEmailAsync(model);

            if (result)
            {
                return Ok("Email updated and confirmation email sent successfully");
            }
            throw new Exception("Email update unsuccessful");
        }

        [Authorize(Roles = "Admin")]
        [HttpPatch("{id}/change-roles")]
        public async Task<IActionResult> UpdateEmail([FromRoute] string id, UserRoleChangeViewModel model)
        {
            var result = await _userService.ChangeUserRolesAsync(id, model);
            if (result)
            {
                return Ok("User roles updated successfully");
            }
            throw new Exception("User roles update unsuccessful");
        }

    }
}

