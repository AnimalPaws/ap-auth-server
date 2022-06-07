using Microsoft.AspNetCore.Mvc;
using ap_auth_server.Services;
using Microsoft.Extensions.Options;
using ap_auth_server.Helpers;
using ap_auth_server.Models.Users;
using ap_auth_server.Models.Foundation;
using ap_auth_server.Models.Veterinary;
using AutoMapper;
using ap_auth_server.Authorization;
using ap_auth_server.Autherization;
using ap_auth_server.Models;

namespace ap_auth_server.Controllers
{
    [Authorize]
    [ApiController]
    [Route("auth")]

    public class AuthController : ControllerBase
    {
        private IUserService _userService;
        private IFoundationService _foundationService;
        private IVeterinaryService _veterinaryService;
        private IMapper _mapper;
        private DataContext _dataContext;
        private readonly AppSettings _appSettings;

        // CONSTRUCTOR THAT CONTAINS METHODS
        public AuthController(
            IUserService userService,
            IFoundationService foundationService,
            IVeterinaryService veterinaryService,
            IMapper mapper,
            DataContext dataContext,
            IOptions<AppSettings> appSettings)
        {
            _userService = userService;
            _foundationService = foundationService;
            _veterinaryService = veterinaryService;
            _mapper = mapper;
            _dataContext = dataContext;
            _appSettings = appSettings.Value;
        }

        // === AUTHENTIFICATION ===

        [AllowAnonymous]
        //POST USER LOGIN
        [HttpPost("authenticate/user")]
        public IActionResult UserAuthenticate(AuthenticateRequest model)
        {
            var response = (_dataContext.User.Any(x => x.Email == model.Username) ||
                _dataContext.Foundation.Any(x => x.Email == model.Username) ||
                _dataContext.Veterinary.Any(x => x.Email == model.Username));

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
                message = "Registration successful. Check your email",
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
                message = "Registration successful. Check your email",
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
                message = "Registration successful. Check your email",
                Status = 200
            });
        }
        /*
        // VERIFICATION OF EMAIL
        [AllowAnonymous]
        [HttpPost("verify-email")]
        public IActionResult VerifyEmail(VerifyEmailRequest model)
        {
            _accountService.VerifyEmail(model.Token);
            return Ok(new
            { 
                message = "Verification successful, you can now login",
                Status = 200
            });
        }

        // RECOVERY AND PASSWORD RESET
        [AllowAnonymous]
        [HttpPost("recovery")]
        public IActionResult RecoveryPassword(RecoveryPasswordRequest model)
        {
            return null;
        }

        [AllowAnonymous]
        [HttpPost("reset-password")]
        public IActionResult ResetPassword(ResetPasswordRequest model)
        {
            _userService.ResetPassword(model);
            return Ok(new 
            { 
                message = "Your password has been changed. Now you can login",
                Status = 200
            });
        }

        // HELPER METHODS
        private void setTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7)
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }*/

        private string ipAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }
    }
}