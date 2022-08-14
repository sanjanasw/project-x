using Microsoft.AspNetCore.Mvc.Versioning;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Predictly_Api.Helpers;
using Project_X.Helpers;
using Project_X.Middlewares.ResponseWrapper.Wrappers;
using System.Net;
using System.Net.Mime;

namespace Project_X.Middlewares.ResponseWrapper
{
    public class ApiResponseWrapperMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IApiVersionReader _apiVersionReader;

        public ApiResponseWrapperMiddleware(RequestDelegate next, IApiVersionReader apiVersionReader)
        {
            _next = next;
            _apiVersionReader = apiVersionReader;
        }

        private string GetVersion(HttpContext context)
        {
#pragma warning disable CS8603 // Possible null reference return.
            return _apiVersionReader.Read(context.Request);
#pragma warning restore CS8603 // Possible null reference return.
        }

        private async Task<string> ReadResponseBodyStreamAsync(Stream bodyStream)
        {
            bodyStream.Seek(0, SeekOrigin.Begin);
            var responseBody = await new StreamReader(bodyStream).ReadToEndAsync();
            bodyStream.Seek(0, SeekOrigin.Begin);
            return responseBody;
        }
        public bool IsValidJson(string text)
        {
            text = text.Trim();
            if ((text.StartsWith("{") && text.EndsWith("}")) || //For object
                (text.StartsWith("[") && text.EndsWith("]"))) //For array
            {
                try
                {
                    var obj = JToken.Parse(text);
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.Request.Path.Value!.Contains("api"))
            {
                var response = new ApiResponse();
                var originalResponseBodyStream = context.Response.Body;
                using var memoryStream = new MemoryStream();

                try
                {
                    context.Response.Body = memoryStream;
                    context.Response.ContentType = MediaTypeNames.Application.Json;
                    await _next.Invoke(context);
                    var bodyAsText = await ReadResponseBodyStreamAsync(memoryStream);
                    context.Response.Body = originalResponseBodyStream;

                    dynamic bodyContent;
                    if (IsValidJson(bodyAsText))
                    {
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
                        bodyContent = JsonConvert.DeserializeObject<dynamic>(bodyAsText);
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
                    }
                    else
                    {
                        bodyContent = bodyAsText;
                    }

#pragma warning disable CS8601 // Possible null reference assignment.
                    response = new ApiResponse
                    {
                        StatusCode = context.Response.StatusCode,
                        Version = GetVersion(context),
                        Result = bodyContent
                    };
#pragma warning restore CS8601 // Possible null reference assignment.

                    if (context.Response.StatusCode == 200)
                        response.Message = "Success";
                }
                catch (Exception ex)
                {
                    response = HandleError(context, ex);
                    context.Response.Body = originalResponseBodyStream;
                }
                finally
                {
                    var text = JsonConvert.SerializeObject(response, Formatting.None,
                        new JsonSerializerSettings
                        {
                            NullValueHandling = NullValueHandling.Ignore
                        });
                    await context.Response.WriteAsync(text);
                }
            }
            else
            {
                try
                {
                    await _next(context);
                }
                catch (Exception ex)
                {
                    await context.Response.WriteAsync(JsonConvert.SerializeObject(HandleError(context, ex)));
                }
            }
        }

        public ApiResponse HandleError(HttpContext context, Exception error)
        {
            context.Response.ContentType = MediaTypeNames.Application.Json;

            switch (error)
            {
                case AppException e:
                    context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    break;
                case KeyNotFoundException e:
                    context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                    break;
                case HumanErrorException e:
                    context.Response.StatusCode = (int)e.Status;
                    return new ApiResponse
                    {
                        StatusCode = (int)e.Status,
                        Version = GetVersion(context),
                        Result = e.Details,
                    };
                default:
                    context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    
                    break;
            }

            return new ApiResponse
            {
                StatusCode = context.Response.StatusCode,
                Version = GetVersion(context),
                Message = error.Message
            };

        }
    }


    public static class ResponseWrapperMiddleware
    {
        public static IApplicationBuilder UseResponseWrapperMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ApiResponseWrapperMiddleware>();
        }
    }
}
