using System.ComponentModel.DataAnnotations;

namespace ap_auth_server.Models.Veterinary
{
    public class AuthenticateRequest
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
