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
using AutoMapper;

namespace ap_auth_server.Controllers
{
    [Microsoft.AspNetCore.Authorization.Authorize]
    [ApiController]
    [Route("auth")]

    public class UserController : ControllerBase
    {
        private IUserService _userService;
        private IMapper _mapper;
        private readonly AppSettings _appSettings;

        public UserController(
            IUserService userService,
            IMapper mapper,
            IOptions<AppSettings> appSettings)
        {
            _userService = userService;
            _mapper = mapper;
            _appSettings = appSettings.Value;
        }


        [AllowAnonymous]
        //POST LOGIN
        [HttpPost("authenticate")]
        public IActionResult Authenticate(AuthenticateRequest model)
        {
            var response = _userService.Authenticate(model);
            return Ok(response);
        }

        [AllowAnonymous]
        //POST REGISTER
        [HttpPost("register")]
        public IActionResult Register(RegisterRequest model)
        {
            _userService.Register(model);
            return Ok(new { message = "Registration successful" });
        }

        [HttpPut("recovery")]
        public async Task<ActionResult> RecoveryPassword(string email)
        {
            return null;
        }
    }
}