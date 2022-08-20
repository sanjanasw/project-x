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

        /// <summary>
        /// Get users details. userid and role can use as a filter(query param).
        /// </summary>
        /// <remarks>
        /// </remarks>
        /// <response code="200">Returns users list</response>
        /// <response code="403">Forbidden</response>
        /// <response code="404">Requested user not found</response>
        [Authorize(Roles = "Admin")]
        [HttpGet]
        public async Task<IActionResult> GetUsers([FromQuery] string? id, [FromQuery] UserRoles? role)
        {
            return Ok(await _userService.GetUsersAsync(role, id));
        }

        /// <summary>
        /// Get user profile.
        /// </summary>
        /// <response code="200">Returns users profile</response>
        /// <response code="404">User not found</response>
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

        /// <summary>
        /// Update user data.
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     PUT /api/v1.0/user/4c7a5bca-395c-45fd-aec4-33064b9af928
        ///     {
        ///         "username": "sanjana",
        ///         "firstName": "sanjana",
        ///         "lastName": "witharanage",
        ///         "email": "sanajnasw99@gmai.com",
        ///     }
        ///
        /// </remarks>
        /// <response code="200">Returns updated user data</response>
        /// <response code="400">Return errors</response>
        /// <response code="404">User not found</response>
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

