using Microsoft.AspNetCore.Mvc;
using ap_auth_server.Models;
using ap_auth_server.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace ap_auth_server.Controllers
{
    [ApiController]
    [Route("auth")]

    public class AuthController : ControllerBase
    {
        //Lectura del contexto de la base de datos
        private readonly ap_dbContext _context;

        //Constructor
        public AuthController(ap_dbContext context)
        {
            _context = context;
        }

        //Post Login
        [HttpPost("login")]
        public IActionResult Login(string email, string password)
        {
            User user = new User();

            try
            {
                if (_context == null)
                {
                    return BadRequest("Fill all fields");
                }
                else
                {
                    if (user.Email != email)
                    {
                        return BadRequest("Account doesn't exists");
                    }
                    else
                    {
                        if (user.Password != password)
                        {
                            return BadRequest(StatusCode(400, "Invalid credentials"));
                        }
                    }

                    if (user.Email == email && user.Password == password)
                    {
                        return Ok("Successful");
                    }
                }
            }

            catch (Exception ex)
            {
                return Content("An error occurred: " + ex.Message);
            }

            return Ok();
        }


        [HttpPost("signup")]
        public async Task<ActionResult> SignUp([FromBody] User user)
        {
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return null;
        }

        [HttpPut("recovery")]
        public async Task<ActionResult> RecoveryPassword(string email)
        {
            return null;
        }

        /*private Token GenerateRefreshToken()
        {
            Token token = new Token();

            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                token.Token = Convert.ToBase64String(randomNumber);
            }
            token.ExpiryDate = DateTime.UtcNow.AddMonths(6);

            return token;
        }

        private string GenerateAccessToken(int userId)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtsettings.SecretKey);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, Convert.ToString(userId))
                }),
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
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
        
        //LOGIN
        /*using (ap_dbContext db = new ap_dbContext())
                {
                    var lst = db.Users.Where(u => u.Email == email && u.Password == password);

                    if (lst.IsNullOrEmpty())
                    {
                        return BadRequest("Account doesn't exists");
                    }

                    if (lst.Count() > 0)
                    {
                        return Ok("Ok");
                    }
                    else
                    {
                        return BadRequest("Invalid Credentials");
                    }
                }*/
    }
}
