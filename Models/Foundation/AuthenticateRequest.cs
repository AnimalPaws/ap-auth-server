using System.ComponentModel.DataAnnotations;

namespace ap_auth_server.Models.Foundation
{
    public class AuthenticateRequest
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
