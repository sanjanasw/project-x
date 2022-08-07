using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Project_X.Business.Interfaces;
using Project_X.Business.ViewModels;
using System.Net.Mime;

namespace Project_X.Controllers
{
    [ApiVersion("1.0")]
    [ApiController]
    [Route("api/v{version:apiVersion}/[controller]")]
    [Produces(MediaTypeNames.Application.Json)]
    [Consumes(MediaTypeNames.Application.Json)]
    public class AccountsController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AccountsController(IAuthService authService) =>
            (_authService) = (authService);

        /// <summary>
        /// Login to the system
        /// </summary>
        /// <param name="model">Email and password are required</param>
        /// <response code="200">Returns user data with JWT</response>
        /// <response code="401">Unothorized user</response>
        [AllowAnonymous]
        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginUserViewModel model)
        {
            var jwtResult = await _authService.SignInJWTAsync(model.Username, model.Password,
                model.RememberMe ? IpAddress() : null);

            if (jwtResult != null)
            {
                return Ok(jwtResult);
            }

            throw new Exception("Incorect username or password");
        }

        [Authorize]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken(RefreshTokenViewModel model)
        {
            var response = await _authService.RefreshTokenAsync(model.RefreshToken, IpAddress());

            if (response == null)
                return Unauthorized(new { message = "Invalid token" });

            return Ok(response);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("revoke-token")]
        public IActionResult RevokeToken(RevokeTokenViewModel model)
        {
            if (string.IsNullOrEmpty(model.RefreshToken))
                return BadRequest(new { message = "Token is required" });

            var response = _authService.RevokeToken(model.RefreshToken, IpAddress());

            if (!response)
                return NotFound(new { message = "Token not found" });

            return Ok(new { message = "Token revoked" });
        }

        [HttpPost("resend-confirm-email")]
        public async Task<IActionResult> ResendConfirmationEmail(ResendConfirmationEmailViewModel model)
        {
            var result = await _authService.ResendConfirmationEmailAsync(model);

            if (result)
            {
                return Ok("Confirmation email resent successfully");
            }
            throw new Exception("Confirmation email resent unsuccessful");
        }

        [HttpPost("verify-email")]
        public async Task<IActionResult> VerifyEmail(ConfirmEmailViewModel model)
        {
            var result = await _authService.VerifyEmailAsync(model);

            if (result)
            {
                return Ok("Email confirmation successfully");
            }
            throw new Exception("Email confirmation unsuccessful");
        }

        [HttpPost("forget-password")]
        public async Task<IActionResult> ForgetPasswrod(ForgetPasswordViewModel model)
        {
            var result = await _authService.ForgetPasswordAsync(model);

            if (result)
            {
                return Ok("Forget password email sent successfully");
            }
            throw new Exception("Password forgeting unsuccessful");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPasswrod(ResetPasswordViewModel model)
        {
            var result = await _authService.ResetPasswordAsync(model);

            if (result)
            {
                return Ok("Password resetting successfully");
            }
            throw new Exception("Password resetting unsuccessful");
        }

        [Authorize]
        [HttpPost("changet-password")]
        public async Task<IActionResult> ChangePasswrod(ChangePasswordViewModel model)
        {
            var result = await _authService.ChangePasswordAsync(model);

            if (result)
            {
                return Ok("Password changed successfully");
            }
            throw new Exception("Password changing unsuccessful");
        }

        private string IpAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
#pragma warning disable CS8602
            return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
#pragma warning restore CS8602
        }
    }
}
