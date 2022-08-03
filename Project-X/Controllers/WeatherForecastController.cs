using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Project_X.Logging.Interfaces;

namespace Project_X.Controllers
{
    [AllowAnonymous]
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private readonly IApplicationLogger<WeatherForecastController> _logger;

        public WeatherForecastController(IApplicationLogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet(Name = "GetWeatherForecast")]
        public IActionResult Get()
        {
            try
            {
                _logger.Info("Test Log");
                var array = new string[] { "dfgdgf", "dgfgd" };
                var x = array[5];
                return Ok(new { Message = "Hello Wold" });
            }
            catch (Exception ex)
            {
                _logger.Error("kelauna", ex);
                throw ex;
            }
        }

        [HttpGet("GetWeatherForecast1")]
        public IActionResult Get1()
        {
            try
            {
                _logger.Info("Test Log");
                var array = new string[] { "dfgdgf", "dgfgd" };
                //var x = array[5];
                return Ok(new { Message = "Hello Wold" });
            }
            catch (Exception ex)
            {
                _logger.Error("kelauna", ex);
                throw ex;
            }
        }
    }
}