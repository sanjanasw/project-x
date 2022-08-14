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
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/v1.0/Accounts/login
        ///     {
        ///        "userName": "sanjana",
        ///        "password": "$Sanjana1"
        ///     }
        ///     
        ///     public route that accepts HTTP POST requests containing a username and password in the body.
        ///     If the username and password are correct then a JWT authentication token and the user details are returned
        ///     in the response body, and a refresh token cookie (HTTP Only) is returned in the response headers.
        /// </remarks>
        /// <param name="model">Email and password are required</param>
        /// <response code="200">Returns user data with JWT</response>
        /// <response code="401">Unothorized user</response>
        [AllowAnonymous]
        [HttpPost("login")]
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

        /// <summary>
        /// Refresh token
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/v1.0/Accounts/refresh-token
        ///     {
        ///        "token": "jkbvjdgj-crgmhcrhngujrchgjhrckjgrg/kg"
        ///     }
        ///     
        ///     public route that accepts HTTP POST requests with a refresh token cookie.
        ///     If the cookie exists and the refresh token is valid then a new JWT authentication token and the user details are
        ///     returned in the response body, a new refresh token cookie (HTTP Only) is returned in the response headers and the old
        ///     refresh token is revoked.
        /// </remarks>
        /// <param name="model"></param>
        /// <response code="200">Returns user data with JWT</response>
        [Authorize]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken(RefreshTokenViewModel model)
        {
            var response = await _authService.RefreshTokenAsync(model.RefreshToken, IpAddress());

            if (response == null)
                return Unauthorized(new { message = "Invalid token" });

            return Ok(response);
        }


        /// <summary>
        /// Revoke refresh token
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/v1.0/Accounts/revoke-token
        ///     {
        ///        "refreshToken": "iugniuguxyfeg08y8y4nuxenhf-x9uef-xnisej"
        ///     }
        ///     
        ///     Secure route that accepts HTTP POST requests containing a refresh token either in the body or in a cookie,
        ///     if both are present the token in the body is used.
        ///     If the refresh token is valid and active then it is revoked and can no longer be used to refresh JWT tokens.
        /// </remarks>
        /// <param name="model"></param>
        /// <response code="200">Returns user data with JWT</response>
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

        /// <summary>
        /// Resend Confirmation Email
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/v1.0/Accounts/resend-confirm-email
        ///     {
        ///         "email": "sanjanasw99@gmail.com",
        ///     }
        ///     
        /// If user havent received verification email on register this end-point can used to resend it, a confirmation email is sending to the email you entered in the registration form. You have to Confirm the email by clicking the confirm button before the link expired(link will expired after 24 hours).
        /// </remarks>
        /// <param name="model"></param>
        /// <response code="200">Returns success message</response>
        /// <response code="400">Already confirmed email</response>
        /// <response code="404">User not found</response>
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

        /// <summary>
        /// Confirm email
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/v1.0/Accounts/verify-email
        ///     {
        ///         "userid": "gfuie-8feiufb-reufberf-rei",
        ///         "token": "kjufbkjdfuirefu8h4r94ruiuwb38dbnie844bu44bi"
        ///     }
        ///
        /// </remarks>
        /// <param name="model"></param>
        /// <response code="200">Returns success message</response>
        /// <response code="400">Invalid token</response>
        /// <response code="404">User not found</response>
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

        /// <summary>
        /// New user account setup
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     PATCH  /api/v1.0/Accounts/new-user-setup
        ///     {
        ///         "userid": "gfuie-8feiufb-reufberf-rei",
        ///         "token": "kjufbkjdfuirefu8h4r94ruiuwb38dbnie844bu44bi",
        ///         "password": "Not@1234"
        ///     }
        ///
        /// </remarks>
        /// <param name="id"></param>
        /// <param name="model"></param>
        /// <response code="200">Returns success message</response>
        /// <response code="400">Invalid token or password doesn't meet minimum requirements</response>
        /// <response code="404">User not found</response>
        [HttpPatch("new-user/{id}")]
        public async Task<IActionResult> NewUserSetup(string id, NewUserSetupViewModel model)
        {
            var result = await _authService.NewUserSetupAsync(model, id);

            if (result)
            {
                return Ok("New user onborded successfully");
            }
            throw new Exception("New user onboarding unsuccessful");
        }

        /// <summary>
        /// Forgot password
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/v1.0/Accounts/forgot-password
        ///     {
        ///         "email": "sanjanasw99@gmail.com"
        ///     }
        ///
        /// </remarks>
        /// <param name="model"></param>
        /// <response code="200">Returns success message</response>
        /// <response code="404">User not found</response>
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

        /// <summary>
        /// Reset password
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/v1.0/Accounts/reset-password
        ///     {
        ///         "userid": "gfuie-8feiufb-reufberf-rei",
        ///         "token": "kjufbkjdfuirefu8h4r94ruiuwb38dbnie844bu44bi",
        ///         "password": "Not@1234"
        ///     }
        ///
        /// </remarks>
        /// <param name="model"></param>
        /// <response code="200">Returns success message</response>
        /// <response code="400">Invalid token</response>
        /// <response code="404">User not found</response>
        [HttpPatch("reset-password")]
        public async Task<IActionResult> ResetPasswrod(ResetPasswordViewModel model)
        {
            var result = await _authService.ResetPasswordAsync(model);

            if (result)
            {
                return Ok("Password resetting successfully");
            }
            throw new Exception("Password resetting unsuccessful");
        }

        /// <summary>
        /// Change password
        /// </summary>
        /// <remarks>
        /// Sample request:
        ///
        ///     POST /api/v1.0/Accounts/change-password
        ///     {
        ///         "currentPassword": "Not@1234",
        ///         "newPassword": "1234@Not"
        ///     }
        ///
        /// </remarks>
        /// <param name="model"></param>
        /// <response code="200">Returns success message</response>
        /// <response code="400">Password doesn't meet minimum requirements</response>
        /// <response code="403">Current password incorrect</response>
        /// <response code="404">User not found</response>
        [Authorize]
        [HttpPut("change-password")]
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
#pragma warning disable CS8602
            return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
#pragma warning restore CS8602
        }
    }
}
