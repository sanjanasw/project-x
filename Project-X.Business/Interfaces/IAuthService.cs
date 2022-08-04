﻿using Project_X.Business.ViewModels;
using Project_X.Data.Models;
using Project_X.Helpers.JWT;

namespace Project_X.Business.Interfaces
{
	public interface IAuthService
	{
		public Task<ApplicationUser> RegisterAdminAsync(RegisterViewModel model);

		public Task<JWTResult> SignInJWTAsync(string username, string password, string? ipAddress = null);

		public Task<JWTResult> RefreshToken(string token, string ipAddress);
	}
}
