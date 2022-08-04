using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Identity;
using Project_X.Common.Enums;

namespace Project_X.Data.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [PersonalData]
        public string? FirstName { get; set; }

        [Required]
        [PersonalData]
        public string? LastName { get; set; }

        public DateTime CreatedOn { get; set; }

        public string? CreatedBy { get; set; }

        public DateTime? ModifiedOn { get; set; }

        public string? ModifiedBy { get; set; }

        public DateTime? DeletedOn { get; set; }

        public string? DeletedBy { get; set; }

        public RecordStatus Status { get; set; }

        public virtual List<RefreshToken> RefreshTokens { get; set; }
    }
}
