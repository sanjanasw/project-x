using Project_X.Data.Models;
using System.ComponentModel.DataAnnotations;

namespace Project_X.Business.ViewModels
{
    public class UserViewModel
    {
        public string Id { get; set; }

        public string FirstName { get; set; }

        public string LastName { get; set; }

        public string Username { get; set; }

        public string Email { get; set; }

        public IList<string> Roles { get; set; }
    }

    public class UserUpdateViewModel
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

    public class UpdateEmailViewModel
    {
        [Required(ErrorMessage = "Username is Required")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Email is Required")]
        public string Email { get; set; }
    }

    public class UserRoleChangeViewModel
    {
        [Required(ErrorMessage = "Roles are Required")]
        public List<string> Roles { get; set; }
    }

    public class ApplicationUserViewModel
    {
        public ApplicationUser ApplicationUser { get; set; }

        public IList<string> Roles { get; set; }
    }
}
