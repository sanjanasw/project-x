using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Predictly_Api.Helpers;
using Project_X.Business.Interfaces;
using Project_X.Business.ViewModels;
using Project_X.Common.Enums;
using Project_X.Data;
using Project_X.Data.Models;
using Project_X.Helpers;
using Project_X.Helpers.JWT;

namespace Project_X.Business
{
    public class AuthService : IAuthService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IMapper _mapper;
        private readonly ILogger<AuthService> _logger;
        private readonly JWTConfigurations _jwtConfigurations;
        private readonly IEmailService _emailService;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthService(ApplicationDbContext context, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
            SignInManager<ApplicationUser> signInManager, IMapper mapper, ILogger<AuthService> logger,
            IOptions<JWTConfigurations> jwtConfigurations, IEmailService emailService, IHttpContextAccessor httpContextAccessor) =>
            (_context, _userManager, _roleManager, _signInManager, _mapper, _logger, _jwtConfigurations, _emailService, _httpContextAccessor) =
            (context, userManager, roleManager, signInManager, mapper, logger, jwtConfigurations.Value, emailService, httpContextAccessor);


        public async Task<JWTResult> SignInJWTAsync(string username, string password, string? ipAddress = null)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(username);

                if (user != null)
                {
                    if (!(await _userManager.IsEmailConfirmedAsync(user)))
                    {
                        throw new HumanErrorException(HttpStatusCode.Forbidden, "Email should verified before login to the system");
                    }

                    var signInResult = await _signInManager.CheckPasswordSignInAsync(user, password, false);
                    if (signInResult != null && signInResult.Succeeded)
                    {
                        var userRoles = await _userManager.GetRolesAsync(user);

                        foreach (var userRole in userRoles)
                        {

                            await _userManager.AddClaimAsync(user,
                                new Claim(ClaimTypes.Role, userRole));
                        }
                        var token = GenerateJWT(user, userRoles);
                        var jwtResult = new JWTResult
                        {
                            Token = new JwtSecurityTokenHandler().WriteToken(token),
                            Expiration = token.ValidTo,
                            User = _mapper.Map<UserViewModel>(user)
                        };

                        if (ipAddress != null)
                        {
                            var tokens = new List<RefreshToken>();
                            var refreshToken = GenerateRefreshToken(ipAddress);
                            tokens.Add(refreshToken);
                            user.RefreshTokens = tokens;
                            _context.Set<ApplicationUser>().Update(user);
                            await _context.SaveChangesAsync();
                            jwtResult.RefreshToken = refreshToken.Token;
                        }
                        _logger.LogInformation(string.Format("{0} logged in to the system", username));
                        return jwtResult;

                    }
                }
                throw new Exception("Incorrect username or password");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }


        public async Task<UserViewModel> CreateUserAsync(RegisterViewModel model, UserRoles role)
        {
            using (var transaction = await _context.Database.BeginTransactionAsync())
            {
                try
                {
                    var user = _mapper.Map<ApplicationUser>(model);
                    var result = await _userManager.CreateAsync(user, model.Password);

                    if (result.Succeeded)
                    {
                        if (!await _roleManager.RoleExistsAsync(UserRoles.Admin.ToString()))
                            await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin.ToString()));
                        if (!await _roleManager.RoleExistsAsync(UserRoles.User.ToString()))
                            await _roleManager.CreateAsync(new IdentityRole(UserRoles.User.ToString()));

                        switch (role)
                        {
                            case UserRoles.Admin:
                                if (await _roleManager.RoleExistsAsync(UserRoles.Admin.ToString()))
                                    await _userManager.AddToRoleAsync(user, UserRoles.Admin.ToString());
                                break;
                            default:
                                if (await _roleManager.RoleExistsAsync(UserRoles.User.ToString()))
                                    await _userManager.AddToRoleAsync(user, UserRoles.User.ToString());
                                break;
                        }
                        string confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        var emailTemplate = new EmailTemplates().GetEmailTemplate(EmailTypes.Verification, user.Email, user, confirmationToken);
                        _emailService.Send(emailTemplate.Email, emailTemplate.Subject, emailTemplate.Html);
                        _logger.LogInformation(string.Format("{0} new {1} registered successfully.", user.UserName, role.ToString()));
                        transaction.Commit();
                        return _mapper.Map<UserViewModel>(user);
                    }

                    _logger.LogWarning(result.Errors.First().Description);
                    transaction.Rollback();
                    throw new HumanErrorException(HttpStatusCode.Conflict, result.Errors);
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    _logger.LogError(ex.Message, ex);
                    throw;
                }
            }
        }

        public async Task<bool> ResendConfirmationEmailAsync(ResendConfirmationEmailViewModel model)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user == null)
                {
                    throw new HumanErrorException(HttpStatusCode.NotFound, "User not found");
                }

                if ((await _userManager.IsEmailConfirmedAsync(user)))
                {
                    throw new HumanErrorException(HttpStatusCode.Forbidden, "Email already confirmed by user");
                }

                string confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var emailTemplate = new EmailTemplates().GetEmailTemplate(EmailTypes.Verification, user.Email, user, confirmationToken);
                _emailService.Send(emailTemplate.Email, emailTemplate.Subject, emailTemplate.Html);
                _logger.LogInformation(string.Format("{0}, confirmation email resent", model.Email));
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        public async Task<bool> VerifyEmailAsync(ConfirmEmailViewModel model)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(model.UserId);
                if (user == null)
                    throw new HumanErrorException(HttpStatusCode.NotFound, "User not found");
                var result = await _userManager.ConfirmEmailAsync(user, model.Token);
                if (result.Succeeded)
                {
                    var emailTemplate = new EmailTemplates().GetEmailTemplate(EmailTypes.Verified, user.Email, user);
                    _emailService.Send(emailTemplate.Email, emailTemplate.Subject, emailTemplate.Html);
                    _logger.LogInformation(string.Format("{0} successfully confirmed email", user.UserName));
                    return true;
                }
                _logger.LogWarning(string.Format("{0} is tried to comfirm email with invalid token", user.UserName));
                throw new HumanErrorException(HttpStatusCode.BadRequest, result.Errors);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        public async Task<bool> ForgetPasswordAsync(ForgetPasswordViewModel model)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user == null)
                {
                    throw new HumanErrorException(HttpStatusCode.NotFound, "User not found");
                }

                if (!(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    throw new HumanErrorException(HttpStatusCode.Forbidden, "Email should verified before forget password");
                }

                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var emailTemplate = new EmailTemplates().GetEmailTemplate(EmailTypes.ResetPassword, user.Email, user, token);
                _emailService.Send(emailTemplate.Email, emailTemplate.Subject, emailTemplate.Html);
                _logger.LogInformation(string.Format("{0} reset password token sent", user.UserName));
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        public async Task<bool> ResetPasswordAsync(ResetPasswordViewModel model)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(model.Userid);

                if (user == null)
                {
                    throw new HumanErrorException(HttpStatusCode.NotFound, "User not found");
                }

                var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

                if (result.Succeeded)
                {
                    var emailTemplate = new EmailTemplates().GetEmailTemplate(EmailTypes.PasswordResetSuccess, user.Email, user);
                    _emailService.Send(emailTemplate.Email, emailTemplate.Subject, emailTemplate.Html);
                    _logger.LogInformation(string.Format("{0} successfully resetted password", user.UserName));
                    return true;
                }

                _logger.LogWarning(string.Format("{0} password reset attempt unsuccessful", user.UserName));
                throw new HumanErrorException(HttpStatusCode.BadRequest, result.Errors);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        public async Task<bool> ChangePasswordAsync(ChangePasswordViewModel model)
        {
            return true;
        }

        public Task SignOutAsync()
        {
            return _signInManager.SignOutAsync();
        }

#pragma warning disable CS8602 // Dereference of a possibly null reference.
        public string GetCurrentLoggedInUsername()
        {
            return _httpContextAccessor.HttpContext.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)
                .Value;
        }

        public string GetApplicationUserId()
        {
            return _httpContextAccessor.HttpContext.User.Claims
                .FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier).Value;
        }
#pragma warning restore CS8602 // Dereference of a possibly null reference.

        public bool RevokeToken(string token, string ipAddress)
        {
            try
            {
                var user = _context.Set<ApplicationUser>().Include(x => x.RefreshTokens)
                .SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));

                // return false if no user found with token
                if (user == null)
                    return false;

                var refreshToken = user.RefreshTokens.SingleOrDefault(x => x.Token == token);

                // return false if token is not active
                if (!refreshToken!.IsActive)
                    return false;

                // revoke token and save
                refreshToken.Revoked = DateTime.UtcNow;
                refreshToken.RevokedByIp = ipAddress;
                _context.Update(user);
                _context.SaveChanges();

                _logger.LogWarning(string.Format("{0}'s refrsh token revoked by {1}", user.UserName, ipAddress));
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        public async Task<JWTResult> RefreshTokenAsync(string token, string ipAddress)
        {
            try
            {
                var user = _context.Set<ApplicationUser>().Include(x => x.RefreshTokens)
                    .SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));

                // return null if no user found with token
                if (user == null)
#pragma warning disable CS8603 // Possible null reference return.
                    return null;

                var refreshToken = user.RefreshTokens.SingleOrDefault(x => x.Token == token);
                // return null if token is no longer active
                if (!refreshToken!.IsActive)
                    return null;
#pragma warning restore CS8603 // Possible null reference return.

                // replace old refresh token with a new one and save
                var newRefreshToken = GenerateRefreshToken(ipAddress);
                refreshToken.Revoked = DateTime.UtcNow;
                refreshToken.RevokedByIp = ipAddress;
                refreshToken.ReplacedByToken = newRefreshToken.Token;
                user.RefreshTokens.Add(newRefreshToken);
                _context.Update(user);
                await _context.SaveChangesAsync();

                var userRoles = await _userManager.GetRolesAsync(user);

                // generate new jwt
                var jwtToken = GenerateJWT(user, userRoles);
                var jwtResult = new JWTResult
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    Expiration = jwtToken.ValidTo,
                    RefreshToken = newRefreshToken.Token
                };

                return jwtResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                throw;
            }
        }

        private RefreshToken GenerateRefreshToken(string ipAddress)
        {
#pragma warning disable SYSLIB0023 // Type or member is obsolete
            using (var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[64];
                rngCryptoServiceProvider.GetBytes(randomBytes);
                return new RefreshToken
                {
                    Token = Convert.ToBase64String(randomBytes),
                    Expires = DateTime.UtcNow.AddDays(7),
                    CreatedByIp = ipAddress
                };
            }
#pragma warning restore SYSLIB0023 // Type or member is obsolete
        }

        private JwtSecurityToken GenerateJWT(ApplicationUser user, IList<string>? userRoles)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.GivenName, user.UserName)
            };

            if (userRoles != null)
            {
                foreach (var userRole in userRoles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, userRole));
                }
            }

#pragma warning disable CS8604 // Possible null reference argument.
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfigurations?.Key));
#pragma warning restore CS8604 // Possible null reference argument.
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            return new JwtSecurityToken(
                _jwtConfigurations.Issuer,
                _jwtConfigurations.Audience,
                claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtConfigurations.Expires),
                signingCredentials: credentials);
        }
    }
}

