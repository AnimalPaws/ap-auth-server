using ap_auth_server.Entities.User;

namespace ap_auth_server.Models.Veterinary
{
    public class VeterinaryAuthenticateResponse
    {
        public int Id { get; set; }
        public string? FirstName { get; set; }
        public string? MiddleName { get; set; }
        public string? Surname { get; set; }
        public string? LastName { get; set; }
        public string? Sex { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
        public string? PhoneNumber { get; set; }
        public DateTime Birthdate { get; set; }
        public string? Department { get; set; }
        public string? City { get; set; }
        public bool? PhoneNumberVerified { get; set; }
        public bool? IsBlocked { get; set; }
        public bool? IsRestricted { get; set; }
        public DateTime? CreatedAt { get; set; }
        public int? ProfileId { get; set; }

        public virtual UserProfile? Profile { get; set; }
        public string? Token { get; internal set; }
    }
}
