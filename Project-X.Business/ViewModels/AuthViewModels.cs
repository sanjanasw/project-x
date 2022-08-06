using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Project_X.Business.ViewModels
{
    [DisplayName("Login User")]
    public class LoginUserViewModel
    {
        /// <summary>
        ///     Registerd username of the user
        /// </summary>
        [Required(ErrorMessage = "Username is required")]

        [Display(Name = "Username", Prompt = "Enter username")]
        public string Username { get; set; }

        /// <summary>
        ///     Password related to the username address
        /// </summary>
        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [Display(Name = "Password", Prompt = "Enter password")]
        public string Password { get; set; }

        /// <summary>
        ///     No need to set in API
        /// </summary>
        [Display(Name = "Remember me")]
        public bool RememberMe { get; set; }
    }

    [DisplayName("Register")]
    public class RegisterViewModel
    {
        [Required]
        [Display(Name = "First name")]
        public string FirstName { get; set; }

        [Required]
        [Display(Name = "Last name")]
        public string LastName { get; set; }

        [Required]
        [Display(Name = "Unique name")]
        public string UserName { get; set; }

        [Required]
        [Display(Name = "Email address")]
        public string Email { get; set; }

        [Display(Name = "Password")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }

    [DisplayName("RevokeToken")]
    public class RefreshTokenRequest
    {
        public string RefreshToken { get; set; }
    }

    public class RevokeTokenRequest
    {
        public string RefreshToken { get; set; }
    }
}

