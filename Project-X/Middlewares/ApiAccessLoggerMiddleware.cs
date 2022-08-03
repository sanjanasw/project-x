using Project_X.Logging.Interfaces;
using System.Security.Claims;

namespace Project_X.Middlewares
{
    public class ApiAccessLoggerMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IApplicationLogger<ApiAccessLoggerMiddleware> _logger;

        public ApiAccessLoggerMiddleware(RequestDelegate next, IApplicationLogger<ApiAccessLoggerMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value != null)
            {
                var info = $"UserId: {context.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value ?? "0"} | Username: {context.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value ?? "anonymous"}| Route: {context.Request.Path.Value}";
                _logger.Info(info);
            }
            await _next(context);
        }
    }

    public static class AccessLoggerMiddleware
    {
        public static IApplicationBuilder UseAccessLoggerMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ApiAccessLoggerMiddleware>();
        }
    }
}
