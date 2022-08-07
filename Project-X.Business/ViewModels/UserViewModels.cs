using Project_X.Data.Models;

namespace Project_X.Business.ViewModels
{
    public class UserViewModel
    {
        public string Id { get; set; }

        public string Name { get; set; }

        public string Username { get; set; }

        public string Email { get; set; }

        public IList<string> Roles { get; set; }
    }

    public class ApplicationUserViewModel
    {
        public ApplicationUser ApplicationUser { get; set; }

        public IList<string> Roles { get; set; }
    }
}
