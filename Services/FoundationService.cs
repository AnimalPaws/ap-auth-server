using AutoMapper;
using BCryptNet = BCrypt.Net.BCrypt;
using ap_auth_server.Helpers;
using ap_auth_server.Authorization;
using ap_auth_server.Entities.Foundations;
using ap_auth_server.Models;
using ap_auth_server.Models.Recovery;
using ap_auth_server.Models.Jwt;
using System.Security.Cryptography;
using ap_auth_server.Entities;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using ap_auth_server.Models.Foundations;

namespace ap_auth_server.Services
{
    public interface IFoundationService
    {
        FoundationAuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
        void Register(FoundationRegisterRequest model, string origin);
        void VerifyEmail(string token);
        void Recovery(RecoveryPasswordRequest model, string origin);
        void ValidateResetToken(ValidateResetTokenRequest model);
        void ResetPassword(ResetPasswordRequest model);
        Foundation GetById(int id);
    }

    public class FoundationService : IFoundationService
    {
        private DataContext _context;
        private IJwtUtils _jwtUtils;
        private readonly IMapper _mapper;
        private readonly AppSettings _appSettings;
        private readonly IEmailService _emailService;

        public FoundationService(
            DataContext context,
            IJwtUtils jwtUtils,
            IMapper mapper,
            IOptions<AppSettings> appSettings,
            IEmailService emailService)
        {
            _context = context;
            _jwtUtils = jwtUtils;
            _mapper = mapper;
            _appSettings = appSettings.Value;
            _emailService = emailService;
        }

        // === AUTHENTIFICATION ===
        public FoundationAuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
        {
            try
            {
                var foundation = _context.Foundation.FirstOrDefault(x => x.Email == model.Username);

                if (model.Username != foundation.Email)
                {
                    throw new AppException("That account doesn't exists");
                }
                //if (foundation.IsVerified)
                //{
                if (foundation == null || !BCryptNet.Verify(model.Password, foundation.Password))
                {
                    throw new AppException("Invalid credentials, please try again");
                }
                //}
                /*else
                {
                    throw new AppException("Please verify your email address");
                }*/

                // Si la validación es correcta, asigna token
                var jwtToken = _jwtUtils.GenerateToken(foundation);
                var handler = new JwtSecurityTokenHandler();
                var decodeValue = handler.ReadJwtToken(jwtToken);

                _context.Update(foundation);
                _context.SaveChanges();

                var response = _mapper.Map<FoundationAuthenticateResponse>(foundation);
                response.Token = jwtToken;
                return response;
            }
            catch (Exception ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        public void Register(FoundationRegisterRequest model, string origin)
        {
            _context.Database.BeginTransaction();
            try
            {
                if (_context.User.Any(x => x.Email == model.Email) ||
                _context.Foundation.Any(x => x.Email == model.Email) ||
                _context.Veterinary.Any(x => x.Email == model.Email))
                {
                    throw new AppException("An account with that email address already exists.");
                }

                if (_context.Foundation.Any(x => x.Name == model.Name))
                {
                    throw new AppException("Foundation {0} already exists", model.Name);
                }

                // Generación del perfil 
                FoundationProfile profile = new FoundationProfile();
                var picture = "https://i.imgur.com/JGmoHaP.jpeg";
                profile.Picture = picture;
                profile.About = "En esta sección se mostrará la información acerca de tu fundación.";
                _context.Foundation_Profile.Add(profile);
                _context.SaveChanges();

                // Mapeo del entidad
                var foundation = _mapper.Map<Foundation>(model);
                foundation.Password = BCryptNet.HashPassword(model.Password);
                foundation.Created_At = DateTime.UtcNow;
                foundation.Role = Role.Foundation;
                foundation.VerificationToken = GenerateVerificationToken();
                foundation.Profile_Id = profile.Id;

                _context.Foundation.Add(foundation);
                _context.SaveChanges();

                _context.Database.CommitTransaction();
                SendVerificationEmail(foundation, origin);
            }
            catch (Exception ex)
            {
                _context.Database.RollbackTransaction();
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        // === TOKENS ===

        public void ValidateResetToken(ValidateResetTokenRequest model)
        {
            GetFoundationByResetToken(model.Token);
        }

        // === VERIFY AND RECOVERY ===
        public void VerifyEmail(string token)
        {
            var foundation = _context.Foundation.SingleOrDefault(x => x.VerificationToken == token);

            if (foundation == null)
                throw new AppException("Verification failed");

            foundation.Verified = DateTime.UtcNow;
            foundation.IsVerified = true;
            foundation.VerificationToken = null;

            _context.Foundation.Update(foundation);
            _context.SaveChanges();
        }

        public void Recovery(RecoveryPasswordRequest model, string origin)
        {
            var foundation = _context.Foundation.SingleOrDefault(x => x.Email == model.Email);

            // always return ok response to prevent email enumeration
            if (foundation == null) return;

            // create reset token that expires after 1 day
            foundation.ResetToken = GenerateResetToken();
            foundation.Reset_Token_Expire = DateTime.UtcNow.AddDays(1);

            _context.Foundation.Update(foundation);
            _context.SaveChanges();

            // send email
            SendPasswordResetEmail(foundation, origin);
        }

        public void ResetPassword(ResetPasswordRequest model)
        {
            var foundation = GetFoundationByResetToken(model.Token);

            // update password and remove reset token
            foundation.Password = BCryptNet.HashPassword(model.Password);
            foundation.PasswordReset = DateTime.UtcNow;
            foundation.ResetToken = null;
            foundation.Reset_Token_Expire = null;

            _context.Foundation.Update(foundation);
            _context.SaveChanges();
        }

        // === HELPER METHODS ===

        private Foundation GetFoundation(int id)
        {
            try
            {
                var foundation = _context.Foundation.Find(id);
                if (foundation == null) throw new KeyNotFoundException("Account not found");
                return foundation;
            }
            catch (Exception ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        private Foundation GetFoundationByResetToken(string token)
        {
            var foundation = _context.Foundation.SingleOrDefault(x =>
                x.ResetToken == token && x.Reset_Token_Expire > DateTime.UtcNow);
            if (foundation == null) throw new AppException("Invalid token");
            return foundation;
        }

        private string GenerateResetToken()
        {
            // token is a cryptographically strong random sequence of values
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

            // ensure token is unique by checking against db
            var tokenIsUnique = !_context.Foundation.Any(x => x.ResetToken == token);
            if (!tokenIsUnique)
                return GenerateResetToken();

            return token;
        }

        private string GenerateVerificationToken()
        {
            // token is a cryptographically strong random sequence of values
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

            // ensure token is unique by checking against db
            var tokenIsUnique = !_context.Foundation.Any(x => x.VerificationToken == token);
            if (!tokenIsUnique)
                return GenerateVerificationToken();

            return token;
        }

        private void SendVerificationEmail(Foundation foundation, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                // origin exists if request sent from browser single page app
                // so send link to verify via single page app
                var verifyUrl = $"{origin}/api/auth/verify-email?token={foundation.VerificationToken}";

                message = $@"
                        <body style=""background-color: #f4f4f4; margin: 0 !important; padding: 0 !important;"">

                            <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"">
                                <tr>
                                    <td bgcolor=""#539be2"" align=""center"">
                                        <table align=""center"" border=""0"" cellspacing=""0"" cellpadding=""0"" width=""600"">
                                        <tr>
                                        <td align=""center"" valign=""top"" width=""600"">
                                        <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""max-width: 600px;"">
                                            <tr>
                                                <td align=""center"" valign=""top"" style=""padding: 40px 10px 40px 10px;"">
                                                    <a href=""{origin}"" target=""_blank"">
                                                        <img alt=""Logo"" src=""https://animalpaws.azurewebsites.net/assets/img/HomeScreen/logo_ap.png"" width=""100%"" height=""100%"" style=""display: block; width: 100%; max-width: 50%; min-width: 40px; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px;"" border=""0"">
                                                    </a>
                                                </td>
                                            </tr>
                                        </table>
                                        </td>
                                        </tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr>
                                    <td bgcolor=""#539be2"" align=""center"" style=""padding: 0px 10px 0px 10px;"">
                                        <table align=""center"" border=""0"" cellspacing=""0"" cellpadding=""0"" width=""600"">
                                        <tr>
                                        <td align=""center"" valign=""top"" width=""600"">
                                        <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""max-width: 600px;"">
                                            <tr>
                                                <td bgcolor=""#ffffff"" align=""center"" valign=""top"" style=""padding: 40px 20px 20px 20px; border-radius: 4px 4px 0px 0px; color: #111111; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 48px; font-weight: 400; letter-spacing: 4px; line-height: 48px;"">
                                                    <h1 style=""font-size: 48px; font-weight: 400; margin: 0;"">CONFIRMACIÓN DE CORREO</h1>
                                                </td>
                                            </tr>
                                        </table>
                                        </td>
                                        </tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr>
                                    <td bgcolor=""#f4f4f4"" align=""center"" style=""padding: 0px 10px 0px 10px;"">
                                        <table align=""center"" border=""0"" cellspacing=""0"" cellpadding=""0"" width=""600"">
                                        <tr>
                                        <td align=""center"" valign=""top"" width=""600"">
                                        <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""max-width: 600px;"">
                                            <tr>
                                                <td bgcolor=""#ffffff"" align=""center"" style=""padding: 20px 30px 40px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;"">
                                                    <p>Hola <strong>{foundation.Name}</strong></p>
                                                    <p>Gracias por unirte e interarse en nuestra comunidad.
                                                        Por favor has clic en el botón de abajo para confirmar tu correo electrónico.</p>
                                                    <a href=""{verifyUrl}""
                                                    style=""background:#20e277;text-decoration:none !important; font-weight:500; margin-top:35px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px"">
                                                    <strong>Confirmar</strong></a>
                                                    <br><br>
                                                    Si el botón no funciona, copia el siguiente 
                                                    <br><br>
                                                    <code>{foundation.VerificationToken}</code>
                                                </td>
                                            </tr>
                                        </table>
                                        </td>
                                        </tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr>
                                    <td bgcolor=""#f4f4f4"" align=""center"" style=""padding: 0px 10px 0px 10px;"">
                                        <table align=""center"" border=""0"" cellspacing=""0"" cellpadding=""0"" width=""600"">
                                        <tr>
                                        <td align=""center"" valign=""top"" width=""600"">
                                        <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""max-width: 600px;"">
                                            <tr>
                                                <td bgcolor=""#f4f4f4"" align=""left"" style=""padding: 30px 30px 30px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 14px; font-weight: 400; line-height: 18px;"">
                                                    <p style=""margin: 0;"">
                                                        <a href=""{origin}"" target=""_blank"" style=""color: #111111; font-weight: 700;"">Inicio</a> –
                                                        <a href=""{origin}/ContactUs"" target=""_blank"" style=""color: #111111; font-weight: 700;"">Soporte</a> –
                                                        <a href=""{origin}/AboutUs"" target=""_blank"" style=""color: #111111; font-weight: 700;"">Sobre Nosotros</a>
                                                    </p>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td bgcolor=""#f4f4f4"" align=""left"" style=""padding: 0px 30px 30px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 14px; font-weight: 400; line-height: 18px;"">
                                                    <p style=""margin: 0;"">&copy; AnimalPaws</p>
                                                </td>
                                            </tr>
                                        </table>
                                        </td>
                                        </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </body>
                        ";
            }
            else
            {
                // origin missing if request sent directly to api
                // so send instructions to verify directly with api
                message = $@"<marginheight=""0"" topmargin=""0"" marginwidth=""0"" style=""margin: 0px; background - color: #f2f3f8;"" leftmargin=""0"">
                            < h1>Verify Email</h1>
                            <img src=""https://animalpaws.azurewebsites.net/assets/img/HomeScreen/logo_ap.png""</img>
                            <p>Please use the below token to verify your email address with the <code>/accounts/verify-email</code> api route:</p>
                            <p><code>{foundation.VerificationToken}</code></p>";
            }

            _emailService.Send(
            to: foundation.Email,
            subject: "AnimalPaws - Confirmación de correo electrónico",
            html: $@"{message}"
            );
        }

        private void SendPasswordResetEmail(Foundation foundation, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                var resetUrl = $"{origin}/api/auth/reset-password?token={foundation.ResetToken}";
                message = $@"
                        <body style=""background-color: #f4f4f4; margin: 0 !important; padding: 0 !important;"">

                            <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"">
                                <tr>
                                    <td bgcolor=""#539be2"" align=""center"">
                                        <table align=""center"" border=""0"" cellspacing=""0"" cellpadding=""0"" width=""600"">
                                        <tr>
                                        <td align=""center"" valign=""top"" width=""600"">
                                        <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""max-width: 600px;"">
                                            <tr>
                                                <td align=""center"" valign=""top"" style=""padding: 40px 10px 40px 10px;"">
                                                    <a href=""{origin}"" target=""_blank"">
                                                        <img alt=""Logo"" src=""https://animalpaws.azurewebsites.net/assets/img/HomeScreen/logo_ap.png"" width=""100%"" height=""100%"" style=""display: block; width: 100%; max-width: 50%; min-width: 40px; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px;"" border=""0"">
                                                    </a>
                                                </td>
                                            </tr>
                                        </table>
                                        </td>
                                        </tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr>
                                    <td bgcolor=""#539be2"" align=""center"" style=""padding: 0px 10px 0px 10px;"">
                                        <table align=""center"" border=""0"" cellspacing=""0"" cellpadding=""0"" width=""600"">
                                        <tr>
                                        <td align=""center"" valign=""top"" width=""600"">
                                        <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""max-width: 600px;"">
                                            <tr>
                                                <td bgcolor=""#ffffff"" align=""center"" valign=""top"" style=""padding: 40px 20px 20px 20px; border-radius: 4px 4px 0px 0px; color: #111111; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 48px; font-weight: 400; letter-spacing: 4px; line-height: 48px;"">
                                                    <h1 style=""font-size: 48px; font-weight: 400; margin: 0;"">REESTABLECER CONTRASEÑA</h1>
                                                </td>
                                            </tr>
                                        </table>
                                        </td>
                                        </tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr>
                                    <td bgcolor=""#f4f4f4"" align=""center"" style=""padding: 0px 10px 0px 10px;"">
                                        <table align=""center"" border=""0"" cellspacing=""0"" cellpadding=""0"" width=""600"">
                                        <tr>
                                        <td align=""center"" valign=""top"" width=""600"">
                                        <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""max-width: 600px;"">
                                            <tr>
                                                <td bgcolor=""#ffffff"" align=""center"" style=""padding: 20px 30px 40px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;"">
                                                    <p>Hola <strong>{foundation.Name}</strong></p>
                                                    <p>Al parecer has olvidado tu contraseña y quiere reestablecerla.
                                                        Por favor has clic en el botón de abajo para cambiar tu contraseña</p>
                                                    <a href=""{resetUrl}""
                                                    style=""background:#20e277;text-decoration:none !important; font-weight:500; margin-top:35px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px"">
                                                    <strong>Reestablecer</strong></a>
                                                    <br><br>
                                                    Si el botón no funciona, copia el siguiente token:
                                                    <br><br>
                                                    <code>{foundation.ResetToken}</code>
                                                </td>
                                            </tr>
                                        </table>
                                        </td>
                                        </tr>
                                        </table>
                                    </td>
                                </tr>
                                <tr>
                                    <td bgcolor=""#f4f4f4"" align=""center"" style=""padding: 0px 10px 0px 10px;"">
                                        <table align=""center"" border=""0"" cellspacing=""0"" cellpadding=""0"" width=""600"">
                                        <tr>
                                        <td align=""center"" valign=""top"" width=""600"">
                                        <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""max-width: 600px;"">
                                            <tr>
                                                <td bgcolor=""#f4f4f4"" align=""left"" style=""padding: 30px 30px 30px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 14px; font-weight: 400; line-height: 18px;"">
                                                    <p style=""margin: 0;"">
                                                        <a href=""{origin}"" target=""_blank"" style=""color: #111111; font-weight: 700;"">Inicio</a> –
                                                        <a href=""{origin}/ContactUs"" target=""_blank"" style=""color: #111111; font-weight: 700;"">Soporte</a> –
                                                        <a href=""{origin}/AboutUs"" target=""_blank"" style=""color: #111111; font-weight: 700;"">Sobre Nosotros</a>
                                                    </p>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td bgcolor=""#f4f4f4"" align=""left"" style=""padding: 0px 30px 30px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 14px; font-weight: 400; line-height: 18px;"">
                                                    <p style=""margin: 0;"">&copy; AnimalPaws</p>
                                                </td>
                                            </tr>
                                        </table>
                                        </td>
                                        </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </body>
                        ";
            }
            else
            {
                message = $@"<p>Please use the below token to reset your password with the <code>/auth/reset-password</code> api route:</p>
                            <p><code>{foundation.ResetToken}</code></p>";
            }

            _emailService.Send(
                to: foundation.Email,
                subject: "AnimalPaws - Reestablecer contraseña",
                html: $@"{message}"
            );
        }

        public Foundation GetById(int id)
        {
            return GetFoundation(id);
        }
    }
}
