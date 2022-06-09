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


namespace ap_auth_server.Services
{
    public interface IUserService
    {
        UserAuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
        UserAuthenticateResponse RefreshToken(string token, string ipAddress);
        void Register(UserRegisterRequest model);
        void RevokeToken(string token, string ipAddress);
        void VerifyEmail(string token);
        void Recovery(ForgotPasswordRequest model, string origin);
        void ValidateResetToken(ValidateResetTokenRequest model);
        void ResetPassword(ResetPasswordRequest model);
        /*IEnumerable<User> GetAll();*/
        User GetById(int id);
        /*void Update(int id, UpdateRequest model);
        void Delete(int id);*/
    }
    public class UserService : IUserService
    {
        private DataContext _context;
        private IJwtUtils _jwtUtils;
        private readonly IMapper _mapper;
        private readonly IEmailService _emailService;

        public UserService(
            DataContext context,
            IJwtUtils jwtUtils,
            IMapper mapper,
            IEmailService emailService)
        {
            _context = context;
            _jwtUtils = jwtUtils;
            _mapper = mapper;
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

                var response = _mapper.Map<UserAuthenticateResponse>(user);
                response.Token = _jwtUtils.GenerateToken(user);
                return response;
            }
            catch (Exception ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        public void Register(UserRegisterRequest model)
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
                _context.User.Add(user);
                _context.SaveChanges();
            }
            catch (Exception ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        // === TOKENS ===
        public UserAuthenticateResponse RefreshToken(string token, string ipAddress)
        {
            var account = getAccountByRefreshToken(token);
            var refreshToken = account.RefreshTokens.Single(x => x.Token == token);

            if (refreshToken.IsRevoked)
            {
                // revoke all descendant tokens in case this token has been compromised
                revokeDescendantRefreshTokens(refreshToken, account, ipAddress, $"Attempted reuse of revoked ancestor token: {token}");
                _context.Update(account);
                _context.SaveChanges();
            }

            if (!refreshToken.IsActive)
                throw new AppException("Invalid token");

            // replace old refresh token with a new one (rotate token)
            var newRefreshToken = rotateRefreshToken(refreshToken, ipAddress);
            account.RefreshTokens.Add(newRefreshToken);


            // remove old refresh tokens from account
            removeOldRefreshTokens(account);

            // save changes to db
            _context.Update(account);
            _context.SaveChanges();

            // generate new jwt
            var jwtToken = _jwtUtils.GenerateJwtToken(account);

            // return data in authenticate response object
            var response = _mapper.Map<AuthenticateResponse>(account);
            response.JwtToken = jwtToken;
            response.RefreshToken = newRefreshToken.Token;
            return response;
        }

        public void RevokeToken(string token, string ipAddress)
        {
            var account = getAccountByRefreshToken(token);
            var refreshToken = account.RefreshTokens.Single(x => x.Token == token);

            if (!refreshToken.IsActive)
                throw new AppException("Invalid token");

            // revoke token and save
            revokeRefreshToken(refreshToken, ipAddress, "Revoked without replacement");
            _context.Update(account);
            _context.SaveChanges();
        }

        public void ValidateResetToken(ValidateResetTokenRequest model)
        {
            getAccountByResetToken(model.Token);
        }

        // === VERIFY AND RECOVERY ===
        public void VerifyEmail(string token)
        {
            var account = _context.User.SingleOrDefault(x => x.VerificationToken == token);

            if (account == null)
                throw new AppException("Verification failed");

            account.Verified = DateTime.UtcNow;
            account.VerificationToken = null;

            _context.User.Update(account);
            _context.SaveChanges();
        }

        public void Recovery(ForgotPasswordRequest model, string origin)
        {
            var account = _context.User.SingleOrDefault(x => x.Email == model.Email);

            // always return ok response to prevent email enumeration
            if (account == null) return;

            // create reset token that expires after 1 day
            account.ResetToken = generateResetToken();
            account.ResetTokenExpires = DateTime.UtcNow.AddDays(1);

            _context.Accounts.Update(account);
            _context.SaveChanges();

            // send email
            sendPasswordResetEmail(account, origin);
        }

        public void ResetPassword(ResetPasswordRequest model)
        {
            var account = getAccountByResetToken(model.Token);

            // update password and remove reset token
            account.PasswordHash = BCrypt.HashPassword(model.Password);
            account.PasswordReset = DateTime.UtcNow;
            account.ResetToken = null;
            account.ResetTokenExpires = null;

            _context.Accounts.Update(account);
            _context.SaveChanges();
        }

        public User GetById(int id)
        {
            try
            {
                return getUser(id);
            }
            catch (Exception ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        private User getUser(int id)
        {
            try
            {
                var user = _context.User.Find(id);
                if (user == null) throw new KeyNotFoundException("User not found");
                return user;
            }
            catch (Exception ex)
            {
                throw new AppException("Something was wrong: {0}", ex);
            }
        }

        // === HELPER METHODS ===
        // helper methods

        private User getAccount(int id)
        {
            var account = _context.User.Find(id);
            if (account == null) throw new KeyNotFoundException("Account not found");
            return account;
        }

        private User getAccountByRefreshToken(string token)
        {
            var account = _context.Accounts.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            if (account == null) throw new AppException("Invalid token");
            return account;
        }

        private User getAccountByResetToken(string token)
        {
            var account = _context.User.SingleOrDefault(x =>
                x.ResetToken == token && x.ResetTokenExpires > DateTime.UtcNow);
            if (account == null) throw new AppException("Invalid token");
            return account;
        }

        private string generateJwtToken(User account)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", account.Id.ToString()) }),
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private string generateResetToken()
        {
            // token is a cryptographically strong random sequence of values
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));

            // ensure token is unique by checking against db
            var tokenIsUnique = !_context.User.Any(x => x.ResetToken == token);
            if (!tokenIsUnique)
                return generateResetToken();

            return token;
        }

        private string generateVerificationToken()
        {
            // token is a cryptographically strong random sequence of values
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));

            // ensure token is unique by checking against db
            var tokenIsUnique = !_context.User.Any(x => x.VerificationToken == token);
            if (!tokenIsUnique)
                return generateVerificationToken();

            return token;
        }

        private RefreshToken rotateRefreshToken(RefreshToken refreshToken, string ipAddress)
        {
            var newRefreshToken = _jwtUtils.GenerateRefreshToken(ipAddress);
            revokeRefreshToken(refreshToken, ipAddress, "Replaced by new token", newRefreshToken.Token);
            return newRefreshToken;
        }

        private void removeOldRefreshTokens(User user)
        {
            user.RefreshTokens.RemoveAll(x =>
                !x.IsActive &&
                x.Created.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
        }

        private void revokeDescendantRefreshTokens(RefreshToken refreshToken, User user, string ipAddress, string reason)
        {
            // recursively traverse the refresh token chain and ensure all descendants are revoked
            if (!string.IsNullOrEmpty(refreshToken.Replaced_By_Token))
            {
                var childToken = user.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken.Replaced_By_Token);
                if (childToken.IsActive)
                    revokeRefreshToken(childToken, ipAddress, reason);
                else
                    revokeDescendantRefreshTokens(childToken, user, ipAddress, reason);
            }
        }

        private void revokeRefreshToken(RefreshToken token, string ipAddress, string reason = null, string replacedByToken = null)
        {
            token.Revoked = DateTime.UtcNow;
            token.Revoked_By_Ip = ipAddress;
            token.Reason_Revoked = reason;
            token.Replaced_By_Token = replacedByToken;
        }

        private void sendVerificationEmail(User user, string origin)
        {
            var email = user.Email;
            string message;
            if (!string.IsNullOrEmpty(origin))
            {
                // origin exists if request sent from browser single page app (e.g. Angular or React)
                // so send link to verify via single page app
                var verifyUrl = $"{origin}/account/verify-email?token={user}";

                message = [email]"<p>Please click the below link to verify your email address:</p <p><a href = ""{verifyUrl}"">{verifyUrl}</a></p>";
            }
            else
            {
                // origin missing if request sent directly to api (e.g. from Postman)
                // so send instructions to verify directly with api
                message = [email]"<p>Please use the below token to verify your email address with the <code>/accounts/verify-email</code> api route:</p>
                            < p >< code >{ user.VerificationToken}</ code ></ p > "";
            }
            _emailService.Send(
            to: account.Email,
            subject: "Sign-up Verification API - Verify Email",
            html: [email]"<h4>Verify Email</h4>
                        < p > Thanks for registering! </ p >
                           { message} ""
            );
        }

        private void sendAlreadyRegisteredEmail(string email, string origin)
        {
            string message;
        }

        private void sendPasswordResetEmail(User user, string origin)
        {
            string message;
        }
    }
}