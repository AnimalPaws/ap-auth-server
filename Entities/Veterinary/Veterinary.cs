using System.Text.Json.Serialization;

namespace ap_auth_server.Entities.Veterinary
{
    public class Veterinary
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public string Deparment { get; set; }
        public string City { get; set; }
        public string Address { get; set; }
        public bool PhoneNumberVerified { get; set; }
        public bool EmailVerified { get; set; }
        public bool IsBlocked { get; set; }
        public bool IsRestricted { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public int? ProfileId { get; set; }
        //public virtual VeterinaryProfile Profile { get; set; }

        [JsonIgnore]
        public string PasswordHash { get; set; }
    }
}
