using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Predictly_Api.Helpers;
using Project_X.Business.Interfaces;
using Project_X.Business.ViewModels;
using Project_X.Common.Enums;
using Project_X.Data.Models;
using Project_X.Helpers;
using Project_X.Services.Interfaces;
using System.Net;

namespace Project_X.Business
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IAuthService _authService;
        private readonly IMapper _mapper;
        private readonly ILogger<UserService> _logger;
        private readonly IEmailService _emailService;

        public UserService(UserManager<ApplicationUser> userManager, IMapper mapper,
            ILogger<UserService> logger, IEmailService emailService, IAuthService authService) =>
            (_userManager, _authService, _mapper, _logger, _emailService) =
            (userManager, authService, mapper, logger, emailService);

        public async Task<object> GetUsersAsync(UserRoles? role, string? id)
        {
            try
            {
                if (id == null)
                {
                    var users = new List<ApplicationUser>();
                    if (role == null)
                    {
                        users = _userManager.Users.ToList();
                    }
                    else
                    {
                        users = (List<ApplicationUser>)await _userManager.GetUsersInRoleAsync(role.ToString());
                    }
                    var usersWithRoles = new List<ApplicationUserViewModel>();
                    foreach (var user in users)
                    {
                        usersWithRoles.Add(new ApplicationUserViewModel
                        {
                            ApplicationUser = user,
                            Roles = await _userManager.GetRolesAsync(user),
                        });
                    }

                    return _mapper.Map<List<UserViewModel>>(usersWithRoles);
                }
                else
                {
                    var user = await _userManager.FindByIdAsync(id);
                    if (user == null)
                    {
                        throw new HumanErrorException(HttpStatusCode.NotFound, "User not found");
                    }
                    var roles = await _userManager.GetRolesAsync(user);
                    return _mapper.Map<UserViewModel>(new ApplicationUserViewModel { ApplicationUser = user, Roles = roles });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        public async Task<UserViewModel> UpdateUserAsync(string userId, UserUpdateViewModel model)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    throw new HumanErrorException(HttpStatusCode.NotFound, "User not found");
                }

                if (user.Email != model.Email)
                {
                    user.EmailConfirmed = false;

                    string confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var emailTemplate = new EmailTemplates().GetEmailTemplate(EmailTypes.Verification, model.Email, user, confirmationToken);
                    _emailService.Send(emailTemplate.Email, emailTemplate.Subject, emailTemplate.Html);
                    _logger.LogInformation(string.Format("{0}, confirmation email sent", model.Email));

                    user.Email = model.Email;
                }

                user.UserName = model.UserName;
                user.FirstName = model.FirstName;
                user.LastName = model.LastName;
                user.ModifiedBy = _authService.GetCurrentLoggedInUsername();
                user.ModifiedOn = DateTime.UtcNow;

                var result = await _userManager.UpdateAsync(user);
                if (result.Succeeded)
                {
                    return _mapper.Map<UserViewModel>(new ApplicationUserViewModel
                    {
                        ApplicationUser = user,
                        Roles = await _userManager.GetRolesAsync(user),
                    });
                }

                throw new HumanErrorException(HttpStatusCode.BadRequest, result.Errors);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        public async Task<bool> UpdateEmailAsync(UpdateEmailViewModel model)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(model.UserName);
                if (user == null)
                {
                    throw new HumanErrorException(HttpStatusCode.NotFound, "User not found");
                }

                if (user.Email == model.Email)
                {
                    throw new HumanErrorException(HttpStatusCode.BadRequest, "Old email and new email cannot be same");
                }

                if (!user.EmailConfirmed)
                {
                    user.Email = model.Email;
                    string confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var emailTemplate = new EmailTemplates().GetEmailTemplate(EmailTypes.Verification, model.Email, user, confirmationToken);
                    _emailService.Send(emailTemplate.Email, emailTemplate.Subject, emailTemplate.Html);
                    _logger.LogInformation(string.Format("{0}, confirmation email sent", model.Email));

                    user.ModifiedBy = "email change flow";
                    user.ModifiedOn = DateTime.UtcNow;
                    var result = await _userManager.UpdateAsync(user);
                    if (result.Succeeded)
                    {
                        return true;
                    }

                    throw new HumanErrorException(HttpStatusCode.BadRequest, result.Errors);
                }
                else
                {
                    throw new HumanErrorException(HttpStatusCode.BadRequest, "User email already confirmed");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        public async Task<bool> UserDeleteAsync(string userId)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    throw new HumanErrorException(HttpStatusCode.NotFound, "User not found");
                }
                user.ModifiedBy = _authService.GetCurrentLoggedInUsername();
                user.ModifiedOn = DateTime.UtcNow;
                user.DeletedBy = _authService.GetCurrentLoggedInUsername();
                user.CreatedOn = DateTime.UtcNow;
                user.Status = RecordStatus.Deleted;

                var result = await _userManager.UpdateAsync(user);
                if (result.Succeeded)
                {
                    return true;
                }

                throw new HumanErrorException(HttpStatusCode.BadRequest, result.Errors);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        public async Task<bool> ChangeUserRolesAsync(string userId, UserRoleChangeViewModel model)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                var currentRoles = await _userManager.GetRolesAsync(user);
                await _userManager.RemoveFromRolesAsync(user, currentRoles);
                var result = await _userManager.AddToRolesAsync(user, (IEnumerable<string>)model.Roles);

                if (result.Succeeded)
                {
                    _logger.LogInformation(string.Format("{0} user's roles changed!", user.UserName));
                    return true;
                }

                throw new HumanErrorException(HttpStatusCode.BadRequest, result.Errors);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw ex;
            }

        }
    }
}
