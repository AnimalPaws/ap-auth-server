using System.ComponentModel.DataAnnotations;
using ap_auth_server.Entities.Foundations;
using ap_auth_server.Entities.Users;
using ap_auth_server.Entities.Veterinaries;
using Microsoft.EntityFrameworkCore;
namespace ap_auth_server.Entities
{
    [Owned]
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }
        public int UserId { get; set; }
        //public int FoundationId { get; set; }
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

        public virtual User User { get; set; }
        //public virtual Foundation Foundation { get; set; }
    }
}