using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Project_X.Business;
using Project_X.Business.Interfaces;
using Project_X.Data;
using Project_X.Data.Models;
using Project_X.Helpers;
using Project_X.Helpers.JWT;
using Project_X.Middlewares;
using Project_X.Middlewares.ResponseWrapper;
using Project_X.SwaggerDocFilters;
using System.Reflection;
using System.Text;

namespace Project_X
{
    public class Startup
    {
        public IConfiguration _configuration { get; }

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            // injecting DbContext to the application
            services.AddDbContext<DbContext, ApplicationDbContext>(options =>
                {
                    options.UseSqlServer(_configuration.GetConnectionString("default"));
                }
            );

            // for Identity  
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            // adding Authentication  
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })

            // adding Jwt Bearer  
            .AddJwtBearer(options =>
            {
                options.SaveToken = true;
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidAudience = _configuration["JWTConfiguration:Audience"],
                    ValidIssuer = _configuration["JWTConfiguration:Issuer"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWTConfiguration:Key"]))
                };
            });

            // injecting swagger
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc(this._configuration.GetValue<string>("Swagger:APIVersion"),
                    new OpenApiInfo
                    {
                        Title = this._configuration.GetValue<string>("Swagger:APITitle"),
                        Version = this._configuration.GetValue<string>("Swagger:APIVersion")
                    });

                var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                c.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));

                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = this._configuration.GetValue<string>("Swagger:OpenApiSecurityScheme:Description"),
                    Name = this._configuration.GetValue<string>("Swagger:OpenApiSecurityScheme:Name"),
                    Type = SecuritySchemeType.ApiKey,
                    BearerFormat = this._configuration.GetValue<string>("Swagger:OpenApiSecurityScheme:BearerFormat"),
                    Scheme = this._configuration.GetValue<string>("Swagger:OpenApiSecurityScheme:Scheme")
                });

                c.OperationFilter<AuthResponsesOperationFilter>();
                c.OperationFilter<RemoveVersionFromParameter>();
                c.DocumentFilter<ReplaceVersionWithExactValueInPath>();

            });

            // injecting versioning
            services.AddApiVersioning(options =>
            {
                options.AssumeDefaultVersionWhenUnspecified = true;
                options.DefaultApiVersion = new Microsoft.AspNetCore.Mvc.ApiVersion(1, 0);
                options.ReportApiVersions = true;
            });

            // auto mapper config
            services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

            // injecting configurations
            services.Configure<JWTConfigurations>(_configuration.GetSection("JWTConfiguration"));
            services.Configure<AppSettings>(_configuration.GetSection("AppSettings"));

            // configure DI for application services
            services.AddScoped<IAuthService, AuthService>();
            services.AddScoped<IEmailService, EmailService>();

            // enable CORS
            services.AddCors(o => o.AddPolicy("AllowAnyOrigin", builder =>
            {
                builder.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
            }));

        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();


            app.UseCors("AllowAnyOrigin");

            app.UseSwagger(c =>
            {
                c.SerializeAsV2 = true;
            });

            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint(this._configuration.GetValue<string>("Swagger:SwaggerUrlRelease"),
                    string.Concat(this._configuration.GetValue<string>("Swagger:APITitle"), ' ', this._configuration.GetValue<string>("Swagger:APIVersion")));
            });

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseAccessLoggerMiddleware();
            app.UseResponseWrapperMiddleware();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGet("/", (context) => context.Response.WriteAsync("API is running..."));
                endpoints.MapControllers();
            });
        }
    }
}