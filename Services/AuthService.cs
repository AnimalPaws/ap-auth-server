using AutoMapper;
using BCryptNet = BCrypt.Net.BCrypt;
using System.Linq;
using System.Collections.Generic;
using ap_auth_server.Models;
using ap_auth_server.Helpers;
using ap_auth_server.Authorization;

namespace ap_auth_server.Services
{
    public interface IAuthService
    {
        AuthenticateResponse Authenticate(AuthenticateRequest model);
        IEnumerable<User> GetAll();
        User GetById(int id);
        void Register(RegisterRequest model);
        void Update(int id, UpdateRequest model);
        void Delete(int id);
    }
    public class AuthService : IAuthService
    {
        private readonly ap_dbContext _context;

        public AuthService(ap_dbContext context)
        {
            _context = context;
        }

        public async Task<bool> SignIn(string email, string password)
        {
            using (ap_dbContext db = new ap_dbContext())
            {
                var lst = db.Users.Where(u => u.Email == email && u.Password == password);
                if (lst == null)
                {
                    return false;
                }
                if (lst.Count() > 0)
                {
                    return Ok("Ok");
                }
                else
                {
                    return BadRequest("Invalid Credentials");
                }
            }
        }
        

        public async Task<bool> SignUp(string username, string password)
        {
            return true;
        }

        public static string CreateNewPassword()
        {
            Random random = new Random(); //Instancia la función random
            string characters = "abcdefghijklmnopqrstuvwxyzABCEFGHIJKLMNOPQRSTUVWXYZ123456789*!.-";
            var newPassword = new char[15]; //Se inicia un arreglo de 15 posiciones
            for (int i = 0; i < newPassword.Length; i++)
            {
                newPassword[i] = characters[random.Next(characters.Length)];
            }
            var password = new string(newPassword);
            return password;
        }
    }
}
