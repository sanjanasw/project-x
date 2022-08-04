﻿using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Project_X.Business.Interfaces;
using Project_X.Business.ViewModels;
using Project_X.Common.Enums;
using Project_X.Data;
using Project_X.Data.Models;
using Project_X.Helpers.JWT;

namespace Project_X.Business
{
	public class AuthService: IAuthService
	{
        private readonly ApplicationDbContext _context;
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
		private readonly ILogger<AuthService> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly JWTConfigurations _jwtConfigurations;

		public AuthService(ApplicationDbContext context, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
            SignInManager<ApplicationUser> signInManager, ILogger<AuthService> logger, IHttpContextAccessor httpContextAccessor,
            IOptions<JWTConfigurations> jwtConfigurations) =>
			(_context, _userManager, _roleManager, _signInManager, _logger, _httpContextAccessor, _jwtConfigurations) =
            (context, userManager, roleManager, signInManager, logger, httpContextAccessor, jwtConfigurations.Value);


        public async Task<JWTResult> SignInJWTAsync(string username, string password, string? ipAddress = null)
        {
            try
            {

                foreach (string? key in _httpContextAccessor.HttpContext.Request.Cookies.Keys)
                {
                    _httpContextAccessor.HttpContext.Response.Cookies.Delete(key);
                }

                var user = await _userManager.FindByNameAsync(username);

                if (user != null)
                {
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
                            Expiration = token.ValidTo
                        };

                        if (ipAddress != null)
                        {
                            var refreshToken = GenerateRefreshToken(ipAddress);
                            user.RefreshTokens.Add(refreshToken);
                            _context.Set<ApplicationUser>().Update(user);
                            await _context.SaveChangesAsync();
                            jwtResult.RefreshToken = refreshToken.Token;
                        }

                        return jwtResult;

                    }
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
            throw new Exception("Incorrect username or password");
        }


        public async Task<ApplicationUser> RegisterAdminAsync(RegisterViewModel model)
        {
            var user = new ApplicationUser
            {
                FirstName = model.FirstName,
                LastName = model.LastName,
                UserName = model.UserName,
                Email = model.Email,
                CreatedBy = "Self Onboarding",
                CreatedOn = DateTime.Now,
                Status = RecordStatus.Active
            };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin.ToString()))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin.ToString()));

            if (await _roleManager.RoleExistsAsync(UserRoles.Admin.ToString()))
                await _userManager.AddToRoleAsync(user, UserRoles.Admin.ToString());

            if (result.Succeeded)
            {
                _logger.LogInformation("new user created");
                return user;
            }

            return null;
        }

        public async Task<JWTResult> RefreshToken(string token, string ipAddress)
        {
            
            var user = _context.Set<ApplicationUser>().SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));

            // return null if no user found with token
            if (user == null) return null;

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            // return null if token is no longer active
            if (!refreshToken.IsActive) return null;

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

        private RefreshToken GenerateRefreshToken(string ipAddress)
        {
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
        }

        private JwtSecurityToken GenerateJWT(ApplicationUser user, IList<string>? userRoles)
        {
            var claims = new List<Claim>();

            claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
            claims.Add(new Claim(ClaimTypes.GivenName, user.UserName));
            if (userRoles != null)
            {
                foreach (var userRole in userRoles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, userRole));
                }
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfigurations.Key));
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
