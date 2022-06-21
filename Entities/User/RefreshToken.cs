using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ap_auth_server.Entities.User
{
    [Owned]
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }
        public User User { get; set; }
        public string? Token { get; set; }
        public string? Created_By_Ip { get; set; }
        public string? Revoked_By_Ip { get; set; }
        public string? Replaced_By_Token { get; set; }
        public string? Reason_Revoked { get; set; }
        public DateTime Created_At { get; set; }
        public DateTime Expire_At { get; set; }
        public DateTime? Revoked { get; set; }
        public bool IsExpired => DateTime.UtcNow >= Expire_At;
        public bool IsRevoked => Revoked != null;
        public bool IsActive => Revoked == null && !IsExpired;
    }
}