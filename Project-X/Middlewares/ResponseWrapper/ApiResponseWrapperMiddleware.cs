using Microsoft.AspNetCore.Mvc.Versioning;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Project_X.Helpers;
using Project_X.Middlewares.ResponseWrapper.Wrappers;
using System.Net;

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
            return _apiVersionReader.Read(context.Request);
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
            if (context.Request.Path.Value.Contains("api"))
            {
                var response = new ApiResponse();
                var originalResponseBodyStream = context.Response.Body;
                using var memoryStream = new MemoryStream();

                try
                {
                    context.Response.Body = memoryStream;
                    context.Response.ContentType = "application/json";
                    await _next.Invoke(context);
                    var bodyAsText = await ReadResponseBodyStreamAsync(memoryStream);
                    context.Response.Body = originalResponseBodyStream;

                    dynamic bodyContent;
                    if (IsValidJson(bodyAsText))
                    {
                        bodyContent = JsonConvert.DeserializeObject<dynamic>(bodyAsText);
                    }
                    else { bodyContent = bodyAsText; }


                    response = new ApiResponse
                    {
                        IsError = false,
                        Message = "Successful",
                        StatusCode = context.Response.StatusCode,
                        Version = GetVersion(context),
                        Result = IsValidJson(bodyAsText) ? JsonConvert.SerializeObject(bodyContent) : bodyAsText
                    };
                }
                catch (Exception ex)
                {
                    response = HandleError(context, ex);
                    context.Response.Body = originalResponseBodyStream;
                }
                finally
                {
                    var text = JsonConvert.SerializeObject(response);
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
            context.Response.ContentType = "application/json";

            switch (error)
            {
                case AppException e:
                    context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    break;
                case KeyNotFoundException e:
                    context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                    break;
                default:
                    // unhandled error
                    context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    break;
            }

            return new ApiResponse
            {
                IsError = true,
                Message = error.GetBaseException().Message,
                StatusCode = context.Response.StatusCode,
                Version = GetVersion(context),
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
