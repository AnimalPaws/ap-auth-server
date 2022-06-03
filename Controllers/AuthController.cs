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

        // === AUTHENTIFICATION ===

        [AllowAnonymous]
        //POST USER LOGIN
        [HttpPost("authenticate/user")]
        public IActionResult UserAuthenticate(UserAuthenticateRequest model)
        {
            var response = _userService.Authenticate(model);
            return Ok(response);
        }

        [AllowAnonymous]
        //POST FOUNDATION LOGIN
        [HttpPost("authenticate/foundation")]
        public IActionResult FoundationAuthenticate(FoundationAuthenticateRequest model)
        {
            var response = _foundationService.Authenticate(model);
            return Ok(response);
        }

        [AllowAnonymous]
        //POST VETERINARY LOGIN
        [HttpPost("authenticate/veterinary")]
        public IActionResult VeterinaryAuthenticate(VeterinaryAuthenticateRequest model)
        {
            var response = _veterinaryService.Authenticate(model);
            return Ok(response);
        }

        // === REGISTRATION ===

        [AllowAnonymous]
        //POST USER REGISTER
        [HttpPost("register/user")]
        public IActionResult UserRegister(UserRegisterRequest model)
        {
            _userService.Register(model);
            return Ok(new 
            { 
                message = "Registration successful {0}", 
                model.Username, 
                Status = 200 
            });
        }

        [AllowAnonymous]
        //POST FOUNDATION REGISTER
        [HttpPost("register/foundation")]
        public IActionResult FoundationRegister(FoundationRegisterRequest model)
        {
            _foundationService.Register(model);
            return Ok(new
            {
                message = "Registration successful {0}",
                model.Name,
                Status = 200
            });
        }

        [AllowAnonymous]
        //POST VETERINARY REGISTER
        [HttpPost("register/veterinary")]
        public IActionResult VeterinaryRegister(VeterinaryRegisterRequest model)
        {
            _veterinaryService.Register(model);
            return Ok(new
            {
                message = "Registration successful {0}",
                model.Name,
                Status = 200
            });
        }


        [HttpPut("recovery")]
        public async Task<ActionResult> RecoveryPassword(string email)
        {
            return null;
        }
    }
}