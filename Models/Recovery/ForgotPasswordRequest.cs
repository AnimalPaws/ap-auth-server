using System.ComponentModel.DataAnnotations;

namespace ap_auth_server.Models.Recovery
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
