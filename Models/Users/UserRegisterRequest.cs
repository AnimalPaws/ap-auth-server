using System.ComponentModel.DataAnnotations;

namespace ap_auth_server.Models.Users
{
    public class UserRegisterRequest
    {
        [Required]
        public string? First_Name { get; set; }
        public string? Middle_Name { get; set; }
        [Required]
        public string? Surname { get; set; }
        [Required]
        public string? Last_Name { get; set; }
        [Required]
        public string? Username { get; set; }
        [Required]
        public string? Sex { get; set; }
        [Required]
        public string? Email { get; set; }
        [Required]
        [MinLength(6)]
        public string? Password { get; set; }
        public string? Phone_Number { get; set; }
        [Required]
        public DateTime Birthdate { get; set; }
        [Required]
        public string? Department { get; set; }
        [Required]
        public string? City { get; set; }
    }
}
