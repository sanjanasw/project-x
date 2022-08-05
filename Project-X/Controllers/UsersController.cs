using Microsoft.AspNetCore.Mvc;
using Project_X.Business.Interfaces;
using Project_X.Business.ViewModels;

namespace Project_X.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/[controller]")]
    public class UsersController : Controller
    {
        private readonly IAuthService _authService;
        private readonly ILogger<UsersController> _logger;

        public UsersController(IAuthService authService, ILogger<UsersController> logger) =>
            (_authService, _logger) = (authService, logger);

        [HttpPost("CreateAdmin")]
        public async Task<IActionResult> CreateAdminAsync(RegisterViewModel model)
        {
            var result = await _authService.CreateAdminAsync(model);
            return Ok(result);
        }
    }
}

