using System.ComponentModel.DataAnnotations;

namespace Project_X.Business.ViewModels
{
    public class LoginUserViewModel
    {
        [Required(ErrorMessage = "Username is required")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

        public bool RememberMe { get; set; }
    }

    public class RegisterViewModel
    {
        [Required(ErrorMessage = "First Name is Required")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "Last Name is Required")]
        public string LastName { get; set; }

        [Required(ErrorMessage = "Username is Required")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Email is Required")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is Required")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }

    public class AdminInviteViewModel
    {
        [Required(ErrorMessage = "First Name is Required")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "Last Name is Required")]
        public string LastName { get; set; }

        [Required(ErrorMessage = "Username is Required")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Email is Required")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }
    }

    public class NewUserSetupViewModel
    {
        [Required(ErrorMessage = "Token is Required")]
        public string Token { get; set; }

        [Required(ErrorMessage = "Password is Required")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }

    public class RefreshTokenViewModel
    {
        [Required(ErrorMessage = "Token is Required")]
        public string RefreshToken { get; set; }
    }

    public class RevokeTokenViewModel
    {
        [Required(ErrorMessage = "Token is Required")]
        public string RefreshToken { get; set; }
    }

    public class ConfirmEmailViewModel
    {
        [Required(ErrorMessage = "UserId is Required")]
        public string UserId { get; set; }

        [Required(ErrorMessage = "Token is Required")]
        public string Token { get; set; }
    }

    public class ForgetPasswordViewModel
    {
        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }
    }

    public class ResetPasswordViewModel
    {
        [Required(ErrorMessage = "User Id is Required")]
        public string Userid { get; set; }

        [Required(ErrorMessage = "Token is Required")]
        public string Token { get; set; }

        [Required(ErrorMessage = "Password is Required")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }

    public class ChangePasswordViewModel
    {
        [Required(ErrorMessage = "Current Password is Required")]
        [DataType(DataType.Password)]
        public string CurrentPassword { get; set; }

        [Required(ErrorMessage = "New Password is Required")]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }
    }

    public class ResendConfirmationEmailViewModel
    {
        [Required(ErrorMessage = "Email is Required")]
        public string Email { get; set; }
    }
}

