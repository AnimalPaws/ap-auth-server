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

        private readonly ap_dbContext _context;
        private readonly JWTSettings _jwtsettings;

        public AuthController(ap_dbContext context, IOptions<JWTSettings> jwtsettings)
        {
            _context = context;
            _jwtsettings = jwtsettings.Value;
        }


        [HttpPost("login")]
        public async Task<ActionResult> Login([FromBody] User user)
        {
            try
            {
                user = await _context.Users.Where(u => u.Email == user.Email && u.Password == user.Password).FirstOrDefault();

                UserWithToken userWithToken = null;

                if (user != null)
                {
                    Token token = GenerateRefreshToken();
                    user.Token.Add(Token);
                    await _context.SaveChangesAsync();

                    userWithToken = new UserWithToken(user);
                    userWithToken.AccessToken = token.Token;
                }

                if (userWithToken != null)
                {
                    return NotFound();
                }

                userWithToken.AccessToken = GenerateAccessToken(user.Id);
                return userWithToken;
            }

            catch (Exception ex)
            {
                return Content("An error occurred: " + ex.Message);
            }
        }


        [HttpPost("signup")]
        public async Task<ActionResult<UserWithToken>> SignUp([FromBody] User user)
        {
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            UserWithToken userWithToken = null;

            if (user != null)
            {
                Token token = GenerateRefreshToken();
                user.Tokens.Add(token);
                await _context.SaveChangesAsync();

                userWithToken = new UserWithToken(user);
                userWithToken.RefreshToken = token.Token;
            }

            if (userWithToken == null)
            {
                return NotFound();
            }

            userWithToken.AccessToken = GenerateAccessToken(user.Id);
            return userWithToken;
        }

        private Token GenerateRefreshToken()
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




        /*private IActionResult BuildToken(User user)
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
        }*/
        
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
