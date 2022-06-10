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
using ap_auth_server.Models.Jwt;
using ap_auth_server.Models.Confirmation;
using ap_auth_server.Models.Recovery;
using ap_auth_server.Entities;

namespace ap_auth_server.Controllers
{
    [Authorize]
    [ApiController]
    [Route("auth")]

    public class AuthController : BaseController
    {
        private IUserService _userService;
        private IFoundationService _foundationService;
        private IVeterinaryService _veterinaryService;
        private IMapper _mapper;
        private DataContext _context;
        private readonly AppSettings _appSettings;

        // CONSTRUCTOR THAT CONTAINS CLASS INSTANCES
        public AuthController(
            IUserService userService,
            IFoundationService foundationService,
            IVeterinaryService veterinaryService,
            IMapper mapper,
            DataContext context,
            IOptions<AppSettings> appSettings)
        {
            _userService = userService;
            _foundationService = foundationService;
            _veterinaryService = veterinaryService;
            _mapper = mapper;
            _context = context;
            _appSettings = appSettings.Value;
        }

        // === AUTHENTIFICATION ===

        [AllowAnonymous]
        //POST USER LOGIN
        [HttpPost("authenticate")]
        public IActionResult UserAuthenticate(AuthenticateRequest model)
        {
            try
            {
                var response = (_context.User.Any(x => x.Email == model.Username) ||
                _context.Foundation.Any(x => x.Email == model.Username) ||
                _context.Veterinary.Any(x => x.Email == model.Username));

                // Accede al servicio y retorna los datos si el email es de USUARIO
                if (response = _context.User.Any(x => x.Email == model.Username))
                {
                    var user = _userService.Authenticate(model, IpAddress());
                    SetTokenCookie(user.RefreshToken);
                    return Ok(user);
                }
                // Accede al servicio y retorna los datos si el email es de FUNDACIÓN
                else if (response = _context.Foundation.Any(x => x.Email == model.Username))
                {
                    var foundation = _foundationService.Authenticate(model, IpAddress());
                    //SetTokenCookie(foundation.RefreshToken);
                    return Ok(foundation);
                }
                // Accede al servicio y retorna los datos si el email es de VETERINARIO
                else if (response = _context.Veterinary.Any(x => x.Email == model.Username))
                {
                    var veterinary = _veterinaryService.Authenticate(model, IpAddress());
                    //SetTokenCookie(veterinary.RefreshToken);
                    return Ok(veterinary);
                }
                return Ok(response);
            }
            catch (BadHttpRequestException ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        // === REGISTRATION ===

        [AllowAnonymous]
        //POST USER REGISTER
        [HttpPost("register/user")]
        public IActionResult UserRegister(UserRegisterRequest model)
        {
            try
            {
                _userService.Register(model, Request.Headers["origin"]);
                return Ok(new
                {
                    message = "Registration successful. Check your email",
                    Status = 200
                });
            }
            catch (BadHttpRequestException ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        [AllowAnonymous]
        //POST FOUNDATION REGISTER
        [HttpPost("register/foundation")]
        public IActionResult FoundationRegister(FoundationRegisterRequest model)
        {
            try
            {
                _foundationService.Register(model);
                return Ok(new
                {
                    message = "Registration successful. Check your email",
                    Status = 200
                });
            }
            catch (BadHttpRequestException ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        [AllowAnonymous]
        //POST VETERINARY REGISTER
        [HttpPost("register/veterinary")]
        public IActionResult VeterinaryRegister(VeterinaryRegisterRequest model)
        {
            try
            {
                _veterinaryService.Register(model);
                return Ok(new
                {
                    message = "Registration successful. Check your email",
                    Status = 200
                });
            }
            catch (BadHttpRequestException ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        // === VERIFY AND RECOVERY ===

        // VERIFICATION OF EMAIL
        [AllowAnonymous]
        [HttpPost("verify-email")]
        public IActionResult VerifyEmail(VerifyEmailRequest model)
        {
            _userService.VerifyEmail(model.Token);
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
            _userService.Recovery(model, Request.Headers["origin"]);
            return Ok(new { message = "Please check your email for password reset instructions" });
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

        // === TOKENS ===
        
        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public ActionResult<UserAuthenticateResponse> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var response = _userService.RefreshToken(refreshToken, IpAddress());
            SetTokenCookie(response.RefreshToken);
            return Ok(response);
        }

        [HttpPost("revoke-token")]
        public IActionResult RevokeToken(RevokeTokenRequest model)
        {
            // accept token from request body or cookie
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            // users can revoke their own tokens and admins can revoke any tokens
            if (!User.OwnsToken(token) && User.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            _userService.RevokeToken(token, IpAddress());
            return Ok(new { message = "Token revoked" });
        }

        [AllowAnonymous]
        [HttpPost("validate-reset-token")]
        public IActionResult ValidateResetToken(ValidateResetTokenRequest model)
        {
            _userService.ValidateResetToken(model);
            return Ok(new { message = "Token is valid" });
        }

        // HELPER METHODS
        private void SetTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7)
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        private string IpAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }
    }
}