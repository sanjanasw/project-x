using System.Security.Claims;

namespace Project_X.Middlewares
{
    public class ApiAccessLoggerMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ApiAccessLoggerMiddleware> _logger;

        public ApiAccessLoggerMiddleware(RequestDelegate next, ILogger<ApiAccessLoggerMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value != null)
            {
                var info = $"Username: {context.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value ?? "anonymous"}| Route: {context.Request.Path.Value}";
                _logger.LogInformation(info);
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
