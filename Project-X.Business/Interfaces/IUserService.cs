using Project_X.Business.ViewModels;
using Project_X.Common.Enums;

namespace Project_X.Business.Interfaces
{
    public interface IUserService
    {
        public Task<List<UserViewModel>> GetUsers(UserRoles role);
    }
}