using System.ComponentModel.DataAnnotations;

namespace ap_auth_server.Models.Foundation
{
    public class FoundationRegisterRequest
    {
        [Required]
        public string? Name { get; set; }
        [Required]
        public string? Email { get; set; }
        [Required]
        public string? Password { get; set; }
        [Required]
        public string? PhoneNumber { get; set; }
        [Required]
        public string? Department { get; set; }
        [Required]
        public string? City { get; set; }
        [Required]
        public string? Address { get; set; }
        public DateTime? CreatedAt { get; set; }
    }
}
