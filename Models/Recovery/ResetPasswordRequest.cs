using System.ComponentModel.DataAnnotations;

namespace ap_auth_server.Models.Recovery
{
    public class ResetPasswordRequest
    {
        [Required]
        public string Token { get; set; }

        [Required]
        [MinLength(6)]
        public string Password { get; set; }

        [Required]
        [Compare("Password", ErrorMessage = "The password doesn't match")]
        public string ConfirmPassword { get; set; }
    }
}
