using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Project_X.Helpers.JWT
{
	public class JWTConfigurations
	{
		public const string AuthSchemes = "Identity.Application," + JwtBearerDefaults.AuthenticationScheme;

        public string? Issuer { get; set; }

        public string? Audience { get; set; }

        public string? Key { get; set; }

        public int Expires { get; set; }
    }
}

