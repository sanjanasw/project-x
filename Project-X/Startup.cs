using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Project_X.Data;
using Project_X.Logging.Interfaces;
using Project_X.Logging.Serilog;
using Project_X.Middlewares;
using Project_X.Middlewares.ResponseWrapper;
using Project_X.SwaggerDocFilters;

namespace Project_X
{
    public class Startup
    {
        private const string API_TITLE = "Swagger:APITitle";
        private const string API_VERSION = "Swagger:APIVersion";
        private const string SWAGGER_URL_RELEASE = "Swagger:SwaggerUrlRelease";
        private const string SECUIRITY_SCHEMA_NAME = "Swagger:OpenApiSecurityScheme:Name";
        private const string SECUIRITY_SCHEMA_DESCRIPTION = "Swagger:OpenApiSecurityScheme:Description";
        private const string SECUIRITY_SCHEMA_FORMAT = "Swagger:OpenApiSecurityScheme:BearerFormat";
        private const string SECUIRITY_SCHEMA = "Swagger:OpenApiSecurityScheme:Scheme";

        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            //injecting DbContext to the application
            services.AddDbContext<DbContext, ApplicationDbContext>(options =>
                {

                    options.UseSqlServer(Configuration.GetConnectionString("default"));
#if DEBUG
                    options.EnableSensitiveDataLogging();
#endif
                }
            );

            //injecting swagger
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc(this.Configuration.GetValue<string>(API_VERSION),
                    new OpenApiInfo
                    {
                        Title = this.Configuration.GetValue<string>(API_TITLE),
                        Version = this.Configuration.GetValue<string>(API_VERSION)
                    });

                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = this.Configuration.GetValue<string>(SECUIRITY_SCHEMA_DESCRIPTION),
                    Name = this.Configuration.GetValue<string>(SECUIRITY_SCHEMA_NAME),
                    Type = SecuritySchemeType.Http,
                    BearerFormat = this.Configuration.GetValue<string>(SECUIRITY_SCHEMA_FORMAT),
                    Scheme = this.Configuration.GetValue<string>(SECUIRITY_SCHEMA)
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type=ReferenceType.SecurityScheme,
                                Id=this.Configuration.GetValue<string>(SECUIRITY_SCHEMA)
                            }
                        },
                        new string[]{}
                    }
                });

                c.OperationFilter<RemoveVersionFromParameter>();
                c.DocumentFilter<ReplaceVersionWithExactValueInPath>();
                c.OperationFilter<AuthResponsesOperationFilter>();

            });

            //injecting versioning
            services.AddApiVersioning(options =>
            {
                options.AssumeDefaultVersionWhenUnspecified = true;
                options.DefaultApiVersion = new Microsoft.AspNetCore.Mvc.ApiVersion(1, 0);
                options.ReportApiVersions = true;
            });

            //injecting logger
            services.AddSingleton(typeof(IApplicationLogger<>), typeof(SerilogLogger<>));
            services.AddControllers();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthorization();

            app.UseAccessLoggerMiddleware();
            app.UseResponseWrapperMiddleware();

            app.UseSwagger();

            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint(this.Configuration.GetValue<string>(SWAGGER_URL_RELEASE), string.Concat(this.Configuration.GetValue<string>(API_TITLE), ' ', this.Configuration.GetValue<string>(API_VERSION)));
            });

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGet("/", (context) => context.Response.WriteAsync("API is running..."));
                endpoints.MapControllers();
            });
        }
    }
}