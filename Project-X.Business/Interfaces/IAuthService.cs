using Project_X.Business.ViewModels;
using Project_X.Data.Models;
using Project_X.Helpers.JWT;

namespace Project_X.Business.Interfaces
{
    public interface IAuthService
    {
        public Task<ApplicationUser> CreateAdminAsync(RegisterViewModel model);

        public Task<JWTResult> SignInJWTAsync(string username, string password, string? ipAddress = null);

        public Task<JWTResult> RefreshTokenAsync(string token, string ipAddress);

        public bool RevokeToken(string token, string ipAddress);

        public Task SignOutAsync();
    }
}

