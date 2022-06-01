using System.ComponentModel.DataAnnotations;

namespace ap_auth_server.Models.Foundation
{
    public class RegisterRequest
    {
        [Required]
        public string FirstName { get; set; }
        public string MiddleName { get; set; }
        [Required]
        public string Surname { get; set; }
        [Required]
        public string LastName { get; set; }
        [Required]
        public string Sex { get; set; }
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
        public string PhoneNumber { get; set; }
        [Required]
        public DateTime Birthdate { get; set; }
        [Required]
        public string Department { get; set; }
        [Required]
        public string City { get; set; }
        public DateTime? CreatedAt { get; set; }
    }
}
