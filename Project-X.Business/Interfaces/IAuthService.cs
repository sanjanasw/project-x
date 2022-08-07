using Project_X.Business.ViewModels;
using Project_X.Common.Enums;
using Project_X.Helpers.JWT;

namespace Project_X.Business.Interfaces
{
    public interface IAuthService
    {
        public Task<UserViewModel> CreateUserAsync(RegisterViewModel model, UserRoles role);

        public Task<JWTResult> SignInJWTAsync(string username, string password, string? ipAddress = null);

        public Task<bool> ResendConfirmationEmailAsync(ResendConfirmationEmailViewModel model);

        public Task<JWTResult> RefreshTokenAsync(string token, string ipAddress);

        public bool RevokeToken(string token, string ipAddress);

        public Task<bool> VerifyEmailAsync(ConfirmEmailViewModel model);

        public Task<bool> ForgetPasswordAsync(ForgetPasswordViewModel model);

        public Task<bool> ResetPasswordAsync(ResetPasswordViewModel model);

        public Task<bool> ChangePasswordAsync(ChangePasswordViewModel model);

        public string GetCurrentLoggedInUsername();

        public string GetLoggedInUserId();

        public Task<UserViewModel> GetCurrentLoggedInUserAsync();

        public Task SignOutAsync();
    }
}

