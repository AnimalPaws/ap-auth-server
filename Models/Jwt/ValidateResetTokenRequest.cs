using System.ComponentModel.DataAnnotations;

namespace ap_auth_server.Models.Jwt
{
    public class ValidateResetTokenRequest
    {
        [Required]
        public string Token { get; set; }
    }
}
