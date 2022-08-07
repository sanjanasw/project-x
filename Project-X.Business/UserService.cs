using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Project_X.Business.Interfaces;
using Project_X.Business.ViewModels;
using Project_X.Common.Enums;
using Project_X.Data;
using Project_X.Data.Models;

namespace Project_X.Business
{
    public class UserService : IUserService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IMapper _mapper;
        private readonly ILogger<UserService> _logger;

        public UserService(ApplicationDbContext context, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
            IMapper mapper, ILogger<UserService> logger) =>
            (_context, _userManager, _roleManager, _mapper, _logger) =
            (context, userManager, roleManager, mapper, logger);

        public async Task<List<UserViewModel>> GetUsers(UserRoles role)
        {
            var users = await _userManager.GetUsersInRoleAsync(UserRoles.Admin.ToString());
            return _mapper.Map<List<UserViewModel>>(users);
        }
    }
}
