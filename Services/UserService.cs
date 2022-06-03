using AutoMapper;
using BCryptNet = BCrypt.Net.BCrypt;
using ap_auth_server.Helpers;
using ap_auth_server.Authorization;
using ap_auth_server.Models.Users;
using ap_auth_server.Entities.User;

namespace ap_auth_server.Services
{
    public interface IUserService
    {
        AuthenticateResponse Authenticate(AuthenticateRequest model);
        void Register(RegisterRequest model);
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

        public UserService(
            DataContext context, 
            IJwtUtils jwtUtils, 
            IMapper mapper)
        {
            _context = context;
            _jwtUtils = jwtUtils;
            _mapper = mapper;
        }

        public AuthenticateResponse Authenticate(AuthenticateRequest model)
        {
            var user = _context.User.SingleOrDefault(x => x.Email == model.Username);
            try
            {
                if(model.Username != user.Email);
            }
            catch (Exception ex)
            {
                throw new AppException("That account doesn't exists");
            }
            /*if(model.Username != user.Email)
            {
                throw new AppException("That account doesn't exists");
            }*/

            if(user == null || !BCryptNet.Verify(model.Password, user.Password))
            {
                throw new AppException("Invalid credentials, please try again");
            }

            var response = _mapper.Map<AuthenticateResponse>(user);
            response.Token = _jwtUtils.GenerateToken(user);
            return response;
        }
        
        public void Register(RegisterRequest model)
        {
            if(_context.User.Any(x => x.Email == model.Email))
            {
                throw new AppException("An account with that email address already exists.");
            }

            if(_context.User.Any(x => x.Username == model.Username))
            {
                throw new AppException("Username {0} is already taken", model.Username);
            }

            var user = _mapper.Map<User>(model);
            user.Password = BCryptNet.HashPassword(model.Password);
            user.Created_At = DateTime.UtcNow;
            _context.User.Add(user);
            _context.SaveChanges();
        }

        public User GetById(int id)
        {
            return getUser(id);
        }

        private User getUser(int id)
        {
            var user = _context.User.Find(id);
            if (user == null) throw new KeyNotFoundException("User not found");
            return user;
        }
    }
}
