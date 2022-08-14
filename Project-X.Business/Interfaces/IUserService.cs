using Project_X.Business.ViewModels;
using Project_X.Common.Enums;

namespace Project_X.Business.Interfaces
{
    public interface IUserService
    {
        public Task<object> GetUsersAsync(UserRoles? role, string? id);

        public Task<UserViewModel> UpdateUserAsync(string userId, UserUpdateViewModel model);

        public Task<bool> UpdateEmailAsync(UpdateEmailViewModel model);

        public Task<bool> UserDeleteAsync(string userId);

        public Task<bool> ChangeUserRolesAsync(string userId, UserRoleChangeViewModel model);
    }
}