using System.ComponentModel.DataAnnotations;

namespace ap_auth_server.Models.Veterinary
{
    public class VeterinaryAuthenticateRequest
    {
        [Required]
        public string? Username { get; set; }
        [Required]
        public string? Password { get; set; }
    }
}
