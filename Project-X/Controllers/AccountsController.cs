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

        public AccountsController(IAuthService authService) =>
            (_authService) = (authService);

        [HttpPost]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            var result = await _authService.RegisterAdminAsync(model);
            if (result != null)
                return Ok(result);

            throw new Exception("faild!");
        }


        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginUserViewModel user)
        {
            var jwtResult = await _authService.SignInJWTAsync(user.Username, user.Password,
                user.RememberMe ? IpAddress() : null);

            if(jwtResult != null)
            {
                //_logger.Info("User logged in. UserName : {0}", user.Username);
                if (user.RememberMe)
                    SetTokenCookie(jwtResult?.RefreshToken);
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
