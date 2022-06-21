using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace ap_auth_server.Entities.User
{
    public class User
    {
        public int? Id { get; set; }
        public string? First_Name { get; set; }
        public string? Middle_Name { get; set; }
        public string? Surname { get; set; }
        public string? Last_Name { get; set; }
        public string? Username { get; set; }
        public string? Sex { get; set; }
        public string? Email { get; set; }
        [JsonIgnore]
        public string? Password { get; set; }
        [NotMapped]
        public Role Role { get; set; }
        public string? Phone_Number { get; set; }
        public DateTime Birthdate { get; set; }
        public string? Department { get; set; }
        public string? City { get; set; }
        public DateTime? Verified { get; set; }
        public bool Phone_Number_Verified { get; set; }
        public bool IsVerified => Verified.HasValue || PasswordReset.HasValue;
        public bool Is_Blocked { get; set; }
        public bool Is_Restricted { get; set; }
        public DateTime? Created_At { get; set; }
        public DateTime? Reset_Token_Expire { get; set; }
        public DateTime? PasswordReset { get; set; }
        public string? VerificationToken { get; set; }
        public string? ResetToken { get; set; }
        public List<RefreshToken> RefreshTokens { get; set; }

        public bool OwnsToken(string token)
        {
            return this.RefreshTokens?.Find(x => x.Token == token) != null;
        }
        public DateTime? Updated_At { get; set; }
        public int? Profile_Id { get; set; }


    }
}
