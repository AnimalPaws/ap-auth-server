using Microsoft.AspNetCore.Mvc;
using ap_auth_server.Models;
using ap_auth_server.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Identity;

namespace ap_auth_server.Controllers
{
    [ApiController]
    [Route("auth")]

    public class AuthController : ControllerBase
    {

        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IConfiguration _configuration;


        [HttpPost("login")]
        public IActionResult Login(string email, string password)
        {
            ap_dbContext dc = new ap_dbContext();
            User user = new User();

            if (dc == null) return BadRequest();

            if (user.Email != email)
            {
                return BadRequest("Account doesn't exists");
            }

            if (user.Password != password)
            {
                return BadRequest("CONTRASEÑA MALA");
            }

            var token = JwtService.Encode(new Dictionary<string, object>
            {
                { "sub", user.Email },
                { "iat", DateTimeOffset.UtcNow },
                { "exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds() }
            });

            return Ok(token);
        }


        [HttpPost("signup")]
        public IActionResult SignUp(User user)
        {
            ap_dbContext dc = new ap_dbContext();
            if(dc == null)
            {
                return BadRequest();
            }

            var token = JwtService.Encode(new Dictionary<string, object>
            {
                { "sub", user.Email },
                { "iat", DateTimeOffset.UtcNow },
                { "exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds() }
            });
            return Accepted(token);
        }

        private IActionResult BuildToken(User user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.UniqueName, user.Email),
                new Claim("key", "jwtkey"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Llave_super_secreta"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var expiration = DateTime.UtcNow.AddHours(1);

            JwtSecurityToken token = new JwtSecurityToken(
               issuer: "localhost",
               audience: "localhost",
               claims: claims,
               expires: expiration,
               signingCredentials: creds);

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = expiration
            });
        }
    }
}
