using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Project_X.Business.ViewModels
{
    public class LoginUserViewModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public bool RememberMe { get; set; }

    }


    public class RegisterViewModel
	{
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}

