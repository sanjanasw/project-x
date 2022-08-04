using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Project_X.Business.Interfaces;
using Project_X.Business.ViewModels;

namespace Project_X.Controllers
{
    [AllowAnonymous]
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/[controller]")]
    public class AccountsController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AccountsController> _logger;

        public AccountsController(IAuthService authService, ILogger<AccountsController> logger) =>
            (_authService, _logger) = (authService, logger);

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginUserViewModel user)
        {
            var jwtResult = await _authService.SignInJWTAsync(user.Username, user.Password,
                user.RememberMe ? IpAddress() : null);

            if (jwtResult != null)
            {
                _logger.LogInformation("User logged in. UserName : {0}", user.Username);
                if (user.RememberMe)
                    SetTokenCookie(jwtResult.RefreshToken);
                return Ok(jwtResult);
            }

            throw new Exception("Incorect username or password");
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var response = await _authService.RefreshToken(refreshToken, IpAddress());

            if (response == null)
                return Unauthorized(new { message = "Invalid token" });

            SetTokenCookie(response.RefreshToken);

            return Ok(response);
        }

        [HttpPost]
        //[Authorize(Roles = "Admin")]
        [Route("revoke-token")]
        public IActionResult RevokeToken(RevokeTokenRequest model)
        {
            // accept token from request body or cookie
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            var response = _authService.RevokeToken(token, IpAddress());

            if (!response)
                return NotFound(new { message = "Token not found" });

            return Ok(new { message = "Token revoked" });
        }

        private string IpAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }

        private void SetTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7)
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }
    }
}
