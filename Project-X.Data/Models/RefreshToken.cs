using System.ComponentModel;
using Project_X.Data.General;

namespace Project_X.Data.Models
{
    [DisplayName("RefreshToken")]
    public class RefreshToken : DataRecord
    {
        public string? Token { get; set; }

        public DateTime Expires { get; set; }

        public bool IsExpired => DateTime.UtcNow >= Expires;

        public string? CreatedByIp { get; set; }

        public DateTime? Revoked { get; set; }

        public string? RevokedByIp { get; set; }

        public string? ReplacedByToken { get; set; }

        public bool IsActive => Revoked == null && !IsExpired;

        public string ApplicationUserId { get; set; }
    }
}

