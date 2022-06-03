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
using ap_auth_server.Helpers;
using ap_auth_server.Authorization;
using Microsoft.AspNetCore.Authorization;
using ap_auth_server.Models.Users;
using ap_auth_server.Models.Foundation;
using ap_auth_server.Models.Veterinary;
using AutoMapper;

namespace ap_auth_server.Controllers
{
    [Microsoft.AspNetCore.Authorization.Authorize]
    [ApiController]
    [Route("auth")]

    public class AuthController : ControllerBase
    {
        private IUserService _userService;
        private IFoundationService _foundationService;
        private IVeterinaryService _veterinaryService;
        private IMapper _mapper;
        private readonly AppSettings _appSettings;

        public AuthController(
            IUserService userService,
            IFoundationService foundationService,
            IVeterinaryService veterinaryService,
            IMapper mapper,
            IOptions<AppSettings> appSettings)
        {
            _userService = userService;
            _foundationService = foundationService;
            _veterinaryService = veterinaryService;
            _mapper = mapper;
            _appSettings = appSettings.Value;
        }


        [AllowAnonymous]
        //POST LOGIN
        [HttpPost("authenticate")]
        public IActionResult Authenticate(Models.Users.AuthenticateRequest model)
        {
            var response = _userService.Authenticate(model);
            return Ok(response);
        }

        [AllowAnonymous]
        //POST USER REGISTER
        [HttpPost("user")]
        public IActionResult UserRegister(Models.Users.RegisterRequest model)
        {
            _userService.Register(model);
            return Ok(new { message = "Registration successful {0}", 
                model.Username, 
                Status = 200 });
        }

        /*[AllowAnonymous]
        //POST FOUNDATION REGISTER
        [HttpPost("foundation")]
        public IActionResult FoundationRegister(Models.Foundation.RegisterRequest model)
        {
            _foundationService.Register(model);
            return Ok(new
            {
                message = "Registration successful {0}",
                model.Name,
                Status = 200
            });
        }*/

        /*[AllowAnonymous]
        //POST VETERINARY REGISTER
        [HttpPost("veterinary")]
        public IActionResult VeterinaryRegister(Models.Veterinary.RegisterRequest model)
        {
            _veterinaryService.Register(model);
            return Ok(new
            {
                message = "Registration successful {0}",
                model.Name,
                Status = 200
            });
        }*/


        [HttpPut("recovery")]
        public async Task<ActionResult> RecoveryPassword(string email)
        {
            return null;
        }
    }
}