using Microsoft.AspNetCore.Mvc;
using ap_auth_server.Services;
using Microsoft.Extensions.Options;
using ap_auth_server.Helpers;
using ap_auth_server.Models.Users;
using ap_auth_server.Models.Foundations;
using ap_auth_server.Models.Veterinaries;
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
                var response = (_context.User.Any(x => x.Email == model.Username) &&
                    (_context.Foundation.Any(x => x.Email == model.Username)) &&
                    (_context.Veterinary.Any(x => x.Email == model.Username)));

                // Accede al servicio y retorna los datos si el email es de USUARIO
                if (response = _context.User.Any(x => x.Email == model.Username))
                {
                    var user = _userService.Authenticate(model, IpAddress());
                    SetTokenCookie(user.Token);
                    return Ok(new
                    {
                        message = "Logged successful",
                        Status = 200
                    });
                }
                // Accede al servicio y retorna los datos si el email es de FUNDACIÓN
                else if (response = _context.Foundation.Any(x => x.Email == model.Username))
                {
                    var foundation = _foundationService.Authenticate(model, IpAddress());
                    SetTokenCookie(foundation.Token);
                    return Ok(new
                    {
                        message = "Logged successful",
                        Status = 200
                    });
                }
                // Accede al servicio y retorna los datos si el email es de VETERINARIO
                else if (response = _context.Veterinary.Any(x => x.Email == model.Username))
                {
                    var veterinary = _veterinaryService.Authenticate(model, IpAddress());
                    SetTokenCookie(veterinary.Token);
                    return Ok(new
                    {
                        message = "Logged successful",
                        Status = 200
                    });
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
                _foundationService.Register(model, Request.Headers["origin"]);
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
                _veterinaryService.Register(model, Request.Headers["origin"]);
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
            try
            {
                var response = (_context.User.Any(x => x.VerificationToken == model.Token) ||
                    (_context.Foundation.Any(x => x.VerificationToken == model.Token)) ||
                    (_context.Veterinary.Any(x => x.VerificationToken == model.Token)));

                if (response = _context.User.Any(x => x.VerificationToken == model.Token))
                {
                    _userService.VerifyEmail(model.Token);
                    return Ok(new
                    {
                        message = "Verification successful, you can now login",
                        Status = 200
                    });
                }
                
                else if (response = _context.Foundation.Any(x => x.VerificationToken == model.Token))
                {
                    _foundationService.VerifyEmail(model.Token);
                    return Ok(new
                    {
                        message = "Verification successful, you can now login",
                        Status = 200
                    });
                }

                else if (response = _context.Veterinary.Any(x => x.VerificationToken == model.Token))
                {
                    _veterinaryService.VerifyEmail(model.Token);
                    return Ok(new
                    {
                        message = "Verification successful, you can now login",
                        Status = 200
                    });
                }

                return Ok(response);
            }
            catch (BadHttpRequestException ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        // RECOVERY AND PASSWORD RESET
        [AllowAnonymous]
        [HttpPost("recovery")]
        public IActionResult RecoveryPassword(RecoveryPasswordRequest model)
        {
            try
            {
                var response = (_context.User.Any(x => x.Email == model.Email) |
                    (_context.Foundation.Any(x => x.Email == model.Email)) ||
                    (_context.Veterinary.Any(x => x.Email == model.Email)));

                if (response = _context.User.Any(x => x.Email == model.Email))
                {
                    _userService.Recovery(model, Request.Headers["origin"]);
                    return Ok(new { 
                        message = "Please check your email for password reset instructions", 
                        Status = 200
                    });
                }

                else if (response = _context.Foundation.Any(x => x.Email == model.Email))
                {
                    _foundationService.Recovery(model, Request.Headers["origin"]);
                    return Ok(new
                    {
                        message = "Please check your email for password reset instructions",
                        Status = 200
                    });
                }

                else if (response = _context.Veterinary.Any(x => x.Email == model.Email))
                {
                    _veterinaryService.Recovery(model, Request.Headers["origin"]);
                    return Ok(new
                    {
                        message = "Verification successful, you can now login",
                        Status = 200
                    });
                }

                return Ok(response);
            }
            catch (BadHttpRequestException ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        [AllowAnonymous]
        [HttpPost("reset-password")]
        public IActionResult ResetPassword(ResetPasswordRequest model)
        {
            try
            {
                var response = (_context.User.Any(x => x.ResetToken == model.Token) ||
                    (_context.Foundation.Any(x => x.ResetToken == model.Token)) ||
                    (_context.Veterinary.Any(x => x.ResetToken == model.Token)));

                if (response = _context.User.Any(x => x.ResetToken == model.Token))
                {
                    _userService.ResetPassword(model);
                    return Ok(new
                    {
                        message = "Your password has been changed. Now you can login",
                        Status = 200
                    });
                }

                else if (response = _context.Foundation.Any(x => x.ResetToken == model.Token))
                {
                    _foundationService.ResetPassword(model);
                    return Ok(new
                    {
                        message = "Your password has been changed. Now you can login",
                        Status = 200
                    });
                }

                else if (response = _context.Veterinary.Any(x => x.ResetToken == model.Token))
                {
                    _veterinaryService.ResetPassword(model);
                    return Ok(new
                    {
                        message = "Your password has been changed. Now you can login",
                        Status = 200
                    });
                }

                return Ok(response);
            }
            catch (BadHttpRequestException ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        // === TOKENS ===

        [AllowAnonymous]
        [HttpPost("validate-reset-token")]
        public IActionResult ValidateResetToken(ValidateResetTokenRequest model)
        {
            try
            {
                var response = (_context.User.Any(x => x.ResetToken == model.Token) ||
                    (_context.Foundation.Any(x => x.ResetToken == model.Token)) ||
                    (_context.Veterinary.Any(x => x.ResetToken == model.Token)));

                if (response = _context.User.Any(x => x.ResetToken == model.Token))
                {
                    _userService.ValidateResetToken(model);
                    return Ok(new
                    {
                        message = "Token is valid",
                        Status = 200
                    });
                }

                else if (response = _context.Foundation.Any(x => x.ResetToken == model.Token))
                {
                    _foundationService.ValidateResetToken(model);
                    return Ok(new
                    {
                        message = "Token is valid",
                        Status = 200
                    });
                }

                else if (response = _context.Veterinary.Any(x => x.ResetToken == model.Token))
                {
                    _veterinaryService.ValidateResetToken(model);
                    return Ok(new
                    {
                        message = "Token is valid",
                        Status = 200
                    });
                }

                return Ok(response);
            }
            catch (BadHttpRequestException ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        // HELPER METHODS
        private void SetTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7)
            };
            Response.Cookies.Append("Token", token, cookieOptions);
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