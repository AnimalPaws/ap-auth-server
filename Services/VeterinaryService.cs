using AutoMapper;
using BCryptNet = BCrypt.Net.BCrypt;
using ap_auth_server.Helpers;
using ap_auth_server.Authorization;
using ap_auth_server.Entities.Veterinaries;
using ap_auth_server.Models;
using ap_auth_server.Models.Recovery;
using ap_auth_server.Models.Jwt;
using System.Security.Cryptography;
using ap_auth_server.Entities;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using ap_auth_server.Models.Veterinaries;

namespace ap_auth_server.Services
{
    public interface IVeterinaryService
    {
        VeterinaryAuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
        void Register(VeterinaryRegisterRequest model, string origin);
        void VerifyEmail(string token);
        void Recovery(RecoveryPasswordRequest model, string origin);
        void ValidateResetToken(ValidateResetTokenRequest model);
        void ResetPassword(ResetPasswordRequest model);
        Veterinary GetById(int id);
    }

    public class VeterinaryService : IVeterinaryService
    {
        private DataContext _context;
        private IJwtUtils _jwtUtils;
        private readonly IMapper _mapper;
        private readonly AppSettings _appSettings;
        private readonly IEmailService _emailService;

        public VeterinaryService(
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
        public VeterinaryAuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
        {
            try
            {
                var veterinary = _context.Veterinary.FirstOrDefault(x => x.Email == model.Username);

                if (model.Username != veterinary.Email)
                {
                    throw new AppException("That account doesn't exists");
                }
                //if (veterinary.IsVerified)
                //{
                if (veterinary == null || !BCryptNet.Verify(model.Password, veterinary.Password))
                {
                    throw new AppException("Invalid credentials, please try again");
                }
                //}
                /*else
                {
                    throw new AppException("Please verify your email address");
                }*/

                // Si la validación es correcta, asigna token
                var jwtToken = _jwtUtils.GenerateToken(veterinary);
                var handler = new JwtSecurityTokenHandler();
                var decodeValue = handler.ReadJwtToken(jwtToken);

                _context.Update(veterinary);
                _context.SaveChanges();

                var response = _mapper.Map<VeterinaryAuthenticateResponse>(veterinary);
                response.Token = jwtToken;
                return response;
            }
            catch (Exception ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        public void Register(VeterinaryRegisterRequest model, string origin)
        {
            _context.Database.BeginTransaction();
            try
            {
                if (_context.User.Any(x => x.Email == model.Email) ||
                _context.Veterinary.Any(x => x.Email == model.Email) ||
                _context.Veterinary.Any(x => x.Email == model.Email))
                {
                    throw new AppException("An account with that email address already exists.");
                }

                if (_context.Veterinary.Any(x => x.Name == model.Name))
                {
                    throw new AppException("Veterinary {0} already exists", model.Name);
                }

                // Mapeo de la entidad
                var veterinary = _mapper.Map<Veterinary>(model);
                var picture = "https://i.imgur.com/JGmoHaP.jpeg";
                veterinary.Picture = picture;
                veterinary.About = "En esta sección se mostrará la información acerca de tu veterinaria.";
                veterinary.Password = BCryptNet.HashPassword(model.Password);
                veterinary.Created_At = DateTime.UtcNow;
                veterinary.Role = Role.Veterinary;
                veterinary.VerificationToken = GenerateVerificationToken();

                _context.Veterinary.Add(veterinary);
                _context.SaveChanges();

                _context.Database.CommitTransaction();
                SendVerificationEmail(veterinary, origin);
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
            GetVeterinaryByResetToken(model.Token);
        }

        // === VERIFY AND RECOVERY ===
        public void VerifyEmail(string token)
        {
            var veterinary = _context.Veterinary.SingleOrDefault(x => x.VerificationToken == token);

            if (veterinary == null)
                throw new AppException("Verification failed");

            veterinary.Verified = DateTime.UtcNow;
            veterinary.IsVerified = true;
            veterinary.VerificationToken = null;

            _context.Veterinary.Update(veterinary);
            _context.SaveChanges();
        }

        public void Recovery(RecoveryPasswordRequest model, string origin)
        {
            var veterinary = _context.Veterinary.SingleOrDefault(x => x.Email == model.Email);

            // always return ok response to prevent email enumeration
            if (veterinary == null) return;

            // create reset token that expires after 1 day
            veterinary.ResetToken = GenerateResetToken();
            veterinary.Reset_Token_Expire = DateTime.UtcNow.AddDays(1);

            _context.Veterinary.Update(veterinary);
            _context.SaveChanges();

            // send email
            SendPasswordResetEmail(veterinary, origin);
        }

        public void ResetPassword(ResetPasswordRequest model)
        {
            var veterinary = GetVeterinaryByResetToken(model.Token);

            // update password and remove reset token
            veterinary.Password = BCryptNet.HashPassword(model.Password);
            veterinary.PasswordReset = DateTime.UtcNow;
            veterinary.ResetToken = null;
            veterinary.Reset_Token_Expire = null;

            _context.Veterinary.Update(veterinary);
            _context.SaveChanges();
        }

        // === HELPER METHODS ===

        private Veterinary GetVeterinary(int id)
        {
            try
            {
                var veterinary = _context.Veterinary.Find(id);
                if (veterinary == null) throw new KeyNotFoundException("Account not found");
                return veterinary;
            }
            catch (Exception ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        private Veterinary GetVeterinaryByResetToken(string token)
        {
            var veterinary = _context.Veterinary.SingleOrDefault(x =>
                x.ResetToken == token && x.Reset_Token_Expire > DateTime.UtcNow);
            if (veterinary == null) throw new AppException("Invalid token");
            return veterinary;
        }

        private string GenerateResetToken()
        {
            // token is a cryptographically strong random sequence of values
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

            // ensure token is unique by checking against db
            var tokenIsUnique = !_context.Veterinary.Any(x => x.ResetToken == token);
            if (!tokenIsUnique)
                return GenerateResetToken();

            return token;
        }

        private string GenerateVerificationToken()
        {
            // token is a cryptographically strong random sequence of values
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

            // ensure token is unique by checking against db
            var tokenIsUnique = !_context.Veterinary.Any(x => x.VerificationToken == token);
            if (!tokenIsUnique)
                return GenerateVerificationToken();

            return token;
        }

        private void SendVerificationEmail(Veterinary veterinary, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                // origin exists if request sent from browser single page app
                // so send link to verify via single page app
                var verifyUrl = $"{origin}/api/auth/verify-email?token={veterinary.VerificationToken}";

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
                                                    <p>Hola <strong>{veterinary.Name}</strong></p>
                                                    <p>Gracias por unirte e interarse en nuestra comunidad.
                                                        Por favor has clic en el botón de abajo para confirmar tu correo electrónico.</p>
                                                    <a href=""{verifyUrl}""
                                                    style=""background:#20e277;text-decoration:none !important; font-weight:500; margin-top:35px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px"">
                                                    <strong>Confirmar</strong></a>
                                                    <br><br>
                                                    Si el botón no funciona, copia el siguiente 
                                                    <br><br>
                                                    <code>{veterinary.VerificationToken}</code>
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
                            <p><code>{veterinary.VerificationToken}</code></p>";
            }

            _emailService.Send(
            to: veterinary.Email,
            subject: "AnimalPaws - Confirmación de correo electrónico",
            html: $@"{message}"
            );
        }

        private void SendPasswordResetEmail(Veterinary veterinary, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                var resetUrl = $"{origin}/api/auth/reset-password?token={veterinary.ResetToken}";
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
                                                    <p>Hola <strong>{veterinary.Name}</strong></p>
                                                    <p>Al parecer has olvidado tu contraseña y quiere reestablecerla.
                                                        Por favor has clic en el botón de abajo para cambiar tu contraseña</p>
                                                    <a href=""{resetUrl}""
                                                    style=""background:#20e277;text-decoration:none !important; font-weight:500; margin-top:35px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px"">
                                                    <strong>Reestablecer</strong></a>
                                                    <br><br>
                                                    Si el botón no funciona, copia el siguiente token:
                                                    <br><br>
                                                    <code>{veterinary.ResetToken}</code>
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
                            <p><code>{veterinary.ResetToken}</code></p>";
            }

            _emailService.Send(
                to: veterinary.Email,
                subject: "AnimalPaws - Reestablecer contraseña",
                html: $@"{message}"
            );
        }

        public Veterinary GetById(int id)
        {
            return GetVeterinary(id);
        }
    }
}
