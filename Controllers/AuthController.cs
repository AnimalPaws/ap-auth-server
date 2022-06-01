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
using ap_auth_server.Services;
using ap_auth_server.Helpers;

namespace ap_auth_server.Controllers
{
    [ApiController]
    [Route("auth")]

    public class AuthController : ControllerBase
    {
        //Lectura del contexto de la base de datos
        private readonly DataContext _context;
        private readonly AuthService _authService;

        //Constructor
        public AuthController(DataContext context, AuthService authService)
        {
            _context = context;
            _authService = authService;
        }

        //Post Login
        [HttpPost("login")]
        public IActionResult Login(string email, string password)
        {
            User user = new User();

            try
            {
                authService.SignIn();
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
