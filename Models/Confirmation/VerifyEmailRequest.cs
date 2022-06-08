using System.ComponentModel.DataAnnotations;

namespace ap_auth_server.Models.Confirmation
{
    public class VerifyEmailRequest
    {
        [Required]
        public string Token { get; set; }
    }
}
