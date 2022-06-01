using System.Text.Json.Serialization;

namespace ap_auth_server.Entities.User
{
    public class User
    {
        public int? Id { get; set; }
        public string? FirstName { get; set; }
        public string? MiddleName { get; set; }
        public string? Surname { get; set; }
        public string? LastName { get; set; }
        public string? Username { get; set; }
        public string? Sex { get; set; }
        public string? Email { get; set; }
        public string? PhoneNumber { get; set; }
        public DateTime Birthdate { get; set; }
        public string? Department { get; set; }
        public string? City { get; set; }
        public bool? PhoneNumberVerified { get; set; }
        public bool EmailVerified { get; set; }
        public bool? IsBlocked { get; set; }
        public bool? IsRestricted { get; set; }
        public DateTime? CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public int? ProfileId { get; set; }

        public virtual UserProfile Profile { get; set; }

        [JsonIgnore]
        public string PasswordHash { get; set; }
    }
}
