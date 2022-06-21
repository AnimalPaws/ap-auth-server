using AutoMapper;
using BCryptNet = BCrypt.Net.BCrypt;
using ap_auth_server.Helpers;
using ap_auth_server.Authorization;
using ap_auth_server.Models.Users;
using ap_auth_server.Entities.User;
using ap_auth_server.Models;
using ap_auth_server.Models.Recovery;
using ap_auth_server.Models.Jwt;
using System.Security.Cryptography;
using ap_auth_server.Entities;
using System.Text;
using Microsoft.Extensions.Options;

namespace ap_auth_server.Services
{
    public interface IUserService
    {
        UserAuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
        UserAuthenticateResponse RefreshToken(string token, string ipAddress);
        void Register(UserRegisterRequest model, string origin);
        void RevokeToken(string token, string ipAddress);
        void VerifyEmail(string token);
        void Recovery(RecoveryPasswordRequest model, string origin);
        void ValidateResetToken(ValidateResetTokenRequest model);
        void ResetPassword(ResetPasswordRequest model);
        User GetById(int id);
    }

    public class UserService : IUserService
    {
        private DataContext _context;
        private IJwtUtils _jwtUtils;
        private readonly IMapper _mapper;
        private readonly AppSettings _appSettings;
        private readonly IEmailService _emailService;

        public UserService(
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
        public UserAuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
        {
            try
            {
                var user = _context.User.FirstOrDefault(x => x.Email == model.Username);

                if (model.Username != user.Email)
                {
                    throw new AppException("That account doesn't exists");
                }
                if (user.IsVerified)
                {
                    if (user == null || !BCryptNet.Verify(model.Password, user.Password))
                    {
                        throw new AppException("Invalid credentials, please try again");
                    }
                }
                else
                {
                    throw new AppException("Please verify your email address");
                }

                // Si la validación es correcta, asigna token y refresh token
                var jwtToken = _jwtUtils.GenerateToken(user);
                var refreshToken = _jwtUtils.GenerateRefreshToken(ipAddress);
                user.RefreshTokens.Add(refreshToken);

                // Elimina antiguos refresh token
                RemoveOldRefreshTokens(user);

                _context.Update(user);
                _context.SaveChanges();

                var response = _mapper.Map<UserAuthenticateResponse>(user);
                response.Token = jwtToken;
                response.RefreshToken = refreshToken.Token;
                return response;
            }
            catch (Exception ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        public void Register(UserRegisterRequest model, string origin)
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

                if (_context.User.Any(x => x.Username == model.Username))
                {
                    throw new AppException("Username {0} is already taken, try with other", model.Username);
                }

                // Generación del perfil
                UserProfile prof = new UserProfile();
                var picture = "https://i.imgur.com/JGmoHaP.jpeg";
                prof.Picture = picture;
                prof.Biography = "En esta sección se mostrarán tus gustos e intereses.";
                _context.User_Profile.Add(prof);
                _context.SaveChanges();

                // Mapeo del usuario
                var user = _mapper.Map<User>(model);
                user.Password = BCryptNet.HashPassword(model.Password);
                user.Created_At = DateTime.UtcNow;
                user.Role = Role.User;
                user.VerificationToken = GenerateVerificationToken();
                user.Profile_Id = prof.Id;

                _context.User.Add(user);
                _context.SaveChanges();

                _context.Database.CommitTransaction();
                SendVerificationEmail(user, origin);
            }
            catch (Exception ex)
            {
                _context.Database.RollbackTransaction();
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        // === TOKENS ===
        public UserAuthenticateResponse RefreshToken(string token, string ipAddress)
        {
            var user = GetUserByRefreshToken(token);
            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            if (refreshToken.IsRevoked)
            {
                // revoke all descendant tokens in case this token has been compromised
                RevokeDescendantRefreshTokens(refreshToken, user, ipAddress, $"Attempted reuse of revoked ancestor token: {token}");
                _context.Update(user);
                _context.SaveChanges();
            }

            if (!refreshToken.IsActive)
                throw new AppException("Invalid token");

            // replace old refresh token with a new one (rotate token)
            var newRefreshToken = RotateRefreshToken(refreshToken, ipAddress);
            user.RefreshTokens.Add(newRefreshToken);


            // remove old refresh tokens from account
            RemoveOldRefreshTokens(user);

            // save changes to db
            _context.Update(user);
            _context.SaveChanges();

            // generate new jwt
            var jwtToken = _jwtUtils.GenerateToken(user);

            // return data in authenticate response object
            var response = _mapper.Map<UserAuthenticateResponse>(user);
            response.Token = jwtToken;
            response.RefreshToken = newRefreshToken.Token;
            return response;
        }

        public void RevokeToken(string token, string ipAddress)
        {
            var user = GetUserByRefreshToken(token);
            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            if (!refreshToken.IsActive)
                throw new AppException("Invalid token");

            // revoke token and save
            RevokeRefreshToken(refreshToken, ipAddress, "Revoked without replacement");
            _context.Update(user);
            _context.SaveChanges();
        }

        public void ValidateResetToken(ValidateResetTokenRequest model)
        {
            GetUserByResetToken(model.Token);
        }

        // === VERIFY AND RECOVERY ===
        public void VerifyEmail(string token)
        {
            var user = _context.User.SingleOrDefault(x => x.VerificationToken == token);

            if (user == null)
                throw new AppException("Verification failed");

            user.Verified = DateTime.UtcNow;
            user.VerificationToken = null;

            _context.User.Update(user);
            _context.SaveChanges();
        }

        public void Recovery(RecoveryPasswordRequest model, string origin)
        {
            var user = _context.User.SingleOrDefault(x => x.Email == model.Email);

            // always return ok response to prevent email enumeration
            if (user == null) return;

            // create reset token that expires after 1 day
            user.ResetToken = GenerateResetToken();
            user.Reset_Token_Expire = DateTime.UtcNow.AddDays(1);

            _context.User.Update(user);
            _context.SaveChanges();

            // send email
            SendPasswordResetEmail(user, origin);
        }

        public void ResetPassword(ResetPasswordRequest model)
        {
            var user = GetUserByResetToken(model.Token);

            // update password and remove reset token
            user.Password = BCryptNet.HashPassword(model.Password);
            user.PasswordReset = DateTime.UtcNow;
            user.ResetToken = null;
            user.Reset_Token_Expire = null;

            _context.User.Update(user);
            _context.SaveChanges();
        }

        // === HELPER METHODS ===

        private User GetUser(int id)
        {
            try
            {
                var user = _context.User.Find(id);
                if (user == null) throw new KeyNotFoundException("Account not found");
                return user;
            }
            catch (Exception ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        private User GetUserByRefreshToken(string token)
        {
            var user = _context.User.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            if (user == null) throw new AppException("Invalid token");
            return user;
        }

        private User GetUserByResetToken(string token)
        {
            var user = _context.User.SingleOrDefault(x =>
                x.ResetToken == token && x.Reset_Token_Expire > DateTime.UtcNow);
            if (user == null) throw new AppException("Invalid token");
            return user;
        }

        private string GenerateResetToken()
        {
            // token is a cryptographically strong random sequence of values
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));

            // ensure token is unique by checking against db
            var tokenIsUnique = !_context.User.Any(x => x.ResetToken == token);
            if (!tokenIsUnique)
                return GenerateResetToken();

            return token;
        }

        private string GenerateVerificationToken()
        {
            // token is a cryptographically strong random sequence of values
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));

            // ensure token is unique by checking against db
            var tokenIsUnique = !_context.User.Any(x => x.VerificationToken == token);
            if (!tokenIsUnique)
                return GenerateVerificationToken();

            return token;
        }

        private RefreshToken RotateRefreshToken(RefreshToken refreshToken, string ipAddress)
        {
            var newRefreshToken = _jwtUtils.GenerateRefreshToken(ipAddress);
            RevokeRefreshToken(refreshToken, ipAddress, "Replaced by new token", newRefreshToken.Token);
            return newRefreshToken;
        }

        private void RemoveOldRefreshTokens(User user)
        {
            user.RefreshTokens.RemoveAll(x =>
                !x.IsActive &&
                x.Created_At.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
        }

        private void RevokeDescendantRefreshTokens(RefreshToken refreshToken, User user, string ipAddress, string reason)
        {
            // recursively traverse the refresh token chain and ensure all descendants are revoked
            if (!string.IsNullOrEmpty(refreshToken.Replaced_By_Token))
            {
                var childToken = user.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken.Replaced_By_Token);
                if (childToken.IsActive)
                    RevokeRefreshToken(childToken, ipAddress, reason);
                else
                    RevokeDescendantRefreshTokens(childToken, user, ipAddress, reason);
            }
        }

        private void RevokeRefreshToken(RefreshToken token, string ipAddress, string reason = null, string replacedByToken = null)
        {
            token.Revoked = DateTime.UtcNow;
            token.Revoked_By_Ip = ipAddress;
            token.Reason_Revoked = reason;
            token.Replaced_By_Token = replacedByToken;
        }

        private void SendVerificationEmail(User user, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                // origin exists if request sent from browser single page app
                // so send link to verify via single page app
                var verifyUrl = $"{origin}/auth/verify-email?token={user.VerificationToken}";

                message = $@"
                        <body style=""background-color: #f4f4f4; margin: 0 !important; padding: 0 !important;"">

                            <div style=""display: none; font-size: 1px; color: #fefefe; line-height: 1px; font-family: 'Lato', Helvetica, Arial, sans-serif; max-height: 0px; max-width: 0px; opacity: 0; overflow: hidden;"">
                                We're thrilled to have you here! Get ready to dive into your new account.
                            </div>

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
                                                    <h1 style=""font-size: 48px; font-weight: 400; margin: 0;"">EMAIL CONFIRMATION</h1>
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
                                        <![endif]–>
                                        <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""max-width: 600px;"">
                                            <!– COPY –>
                                            <tr>
                                                <td bgcolor=""#ffffff"" align=""center"" style=""padding: 20px 30px 40px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;"">
                                                    <p>Hello <strong>{user.Username}</strong></p>
                                                    <p>Thank you for signing up.
                                                        Please click the below button to verify your email address</p>
                                                    <a href=""{verifyUrl}""
                                                    style=""background:#20e277;text-decoration:none !important; font-weight:500; margin-top:35px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px"">
                                                    <strong>Confirm Email</strong></a>
                                                    <br><br>
                                                    If button doesn't work, copy the following token:
                                                    <br><br>
                                                    <code>{user.VerificationToken}</code>
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
                                                        <a href=""{origin}"" target=""_blank"" style=""color: #111111; font-weight: 700;"">Home</a> –
                                                        <a href=""{origin}/ContactUs"" target=""_blank"" style=""color: #111111; font-weight: 700;"">Support</a> –
                                                        <a href=""{origin}/AboutUs"" target=""_blank"" style=""color: #111111; font-weight: 700;"">About Us</a>
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
                            < p>Please use the below token to verify your email address with the <code>/accounts/verify-email</code> api route:</p>
                            <p><code>{user.VerificationToken}</code></p>";
            }

            _emailService.Send(
            to: user.Email,
            subject: "AnimalPaws - Verify Email",
            html: $@"{message}"
            );
        }

        private void SendPasswordResetEmail(User user, string origin)
        {
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                var resetUrl = $"{origin}/auth/reset-password?token={user.ResetToken}";
                message = $@"
                        <div width=""670px"" align=""center"" background=""#fff"" border-color=""black"" border-width=""1px"">
                        <img src=""https://animalpaws.azurewebsites.net/assets/img/HomeScreen/logo_ap.png""></img>
                            <h1 font-size=""32px"">RESET PASSWORD</h1>
                            <span display=""inline-block"" vertical-align=""middle"" margin=""29px 0 26px"" border-bottom=""1px solid #cecece"" width=""100px""></span>
                            <br>
                            <p color:#455056; font-size:20px;line-height:24px; margin:0;>Hello <strong>{user.Username}</strong></p>
                            <p color:#455056; font-size:15px;line-height:24px; margin:0;>We see that you forgot your password.
                                Please click the below button to reset your password</p>
                            <a href=""{resetUrl}""
                            style=""background:#20e277;text-decoration:none !important; font-weight:500; margin-top:35px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px"">
                            Reset Password</a>
                            <code>{user.ResetToken}</code>
                        </div>
                        <p style=""text - align:center;font - size:14px; color: rgba(69, 80, 86, 0.7411764705882353); line - height:18px; margin: 0 0 0;""> &copy; <strong>AnimalPaws</strong></p>""
                        ";
            }
            else
            {
                message = $@"<p>Please use the below token to reset your password with the <code>/auth/reset-password</code> api route:</p>
                            <p><code>{user.ResetToken}</code></p>";
            }

            _emailService.Send(
                to: user.Email,
                subject: "AnimalPaws - Reset Password",
                html: $@"{message}"
            );
        }

        public User GetById(int id)
        {
            return GetUser(id);
        }
    }
}
