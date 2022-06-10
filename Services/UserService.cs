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
        /*IEnumerable<User> GetAll();*/
        /*void Update(int id, UpdateRequest model);
        void Delete(int id);*/
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
            var user = _context.User.SingleOrDefault(x => x.Email == model.Username);
            try
            {
                if (model.Username != user.Email)
                {
                    throw new AppException("That account doesn't exists");
                }

                if (user == null || !BCryptNet.Verify(model.Password, user.Password))
                {
                    throw new AppException("Invalid credentials, please try again");
                }

                // Si la validación es correcta, asigna token y refresh token
                var jwtToken = _jwtUtils.GenerateToken(user);
                var refreshToken = _jwtUtils.GenerateRefreshToken(ipAddress);
                user.RefreshTokens.Add(refreshToken);

                // Elimina antiguos refresh token
                RemoveOldRefreshTokens(user);

                // Guarda cambios
                _context.Update(user);
                _context.SaveChanges();

                var response = _mapper.Map<UserAuthenticateResponse>(user);
                response.Token = _jwtUtils.GenerateToken(user);
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
                    throw new AppException("Username {0} is already taken", model.Username);
                }

                var user = _mapper.Map<User>(model);
                user.Password = BCryptNet.HashPassword(model.Password);
                user.Created_At = DateTime.UtcNow;
                user.Role = Role.User;
                user.VerificationToken = GenerateVerificationToken();

                _context.User.Add(user);
                _context.SaveChanges();

                SendVerificationEmail(user, origin);
            }
            catch (Exception ex)
            {
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
                var verifyUrl = $"{origin}/account/verify-email?token={user.VerificationToken}";

                message = $@"
                        <div width=""670px"" align=""center"" background=""#fff"" border-color=""black"" border-width=""1px"">
                        <img src=""https://animalpaws.azurewebsites.net/assets/img/HomeScreen/logo_ap.png""></img>
                            <h1 font-size=""32px"">EMAIL CONFIRMATION</h1>
                            <span display=""inline-block"" vertical-align=""middle"" margin=""29px 0 26px"" border-bottom=""1px solid #cecece"" width=""100px""></span>
                            <br>
                            <p color:#455056; font-size:15px;line-height:24px; margin:0;>Hello <strong>{user.Username}</strong></p>
                            <p color:#455056; font-size:15px;line-height:24px; margin:0;>Thank you for signing up.
                                Please click the below button to verify your email address</p>
                            <a href=""{verifyUrl}""
                            style=""background:#20e277;text-decoration:none !important; font-weight:500; margin-top:35px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px"">
                            Confirm Email</a>
                        </div>
                        <p style=""text - align:center;font - size:14px; color: rgba(69, 80, 86, 0.7411764705882353); line - height:18px; margin: 0 0 0;""> &copy; <strong>AnimalPaws</strong></p>""
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
                var resetUrl = $"{origin}/account/reset-password?token={user.ResetToken}";
                message = $@"<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                            <p><a href=""{resetUrl}"">{resetUrl}</a></p>";
            }
            else
            {
                message = $@"<p>Please use the below token to reset your password with the <code>/accounts/reset-password</code> api route:</p>
                            <p><code>{user.ResetToken}</code></p>";
            }

            _emailService.Send(
                to: user.Email,
                subject: "AnimalPaws - Reset Password",
                html: $@"<h4>Reset Password Email</h4>
                        {message}"
            );
        }

        public User GetById(int id)
        {
            return GetUser(id);
        }
    }
}
