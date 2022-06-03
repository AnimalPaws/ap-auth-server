using System.ComponentModel.DataAnnotations;

namespace ap_auth_server.Models.Users
{
    public class UserAuthenticateRequest
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
