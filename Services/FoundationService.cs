using AutoMapper;
using BCryptNet = BCrypt.Net.BCrypt;
using ap_auth_server.Helpers;
using ap_auth_server.Authorization;
using ap_auth_server.Models.Foundation;
using ap_auth_server.Entities.Foundation;

namespace ap_auth_server.Services
{
    public interface IFoundationService
    {
        AuthenticateResponse Authenticate(AuthenticateRequest model);
        void Register(RegisterRequest model);
        /*IEnumerable<User> GetAll();*/
        Foundation GetById(int id);
        /*void Update(int id, UpdateRequest model);
        void Delete(int id);*/
    }
    public class FoundationService : IFoundationService
    {
        private DataContext _context;
        private IJwtUtils _jwtUtils;
        private readonly IMapper _mapper;

        public FoundationService(
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
            var foundation = _context.Foundation.SingleOrDefault(x => x.Email == model.Username);

            if(model.Username != foundation.Email)
            {
                throw new AppException("That account doesn't exists");
            }

            if(foundation == null || !BCryptNet.Verify(model.Password, foundation.PasswordHash))
            {
                throw new AppException("Invalid credentials, please try again");
            }

            var response = _mapper.Map<AuthenticateResponse>(foundation);
            response.Token = _jwtUtils.GenerateToken(foundation);
            return response;
        }
        
        public void Register(RegisterRequest model)
        {
            if(_context.Foundation.Any(x => x.Email == model.Email))
            {
                throw new AppException("An account with that email address already exists.");
            }

            if(_context.Foundation.Any(x => x.Name == model.Name))
            {
                throw new AppException("Name {0} is already taken", model.Name);
            }

            var foundation = _mapper.Map<Foundation>(model);
            foundation.PasswordHash = BCryptNet.HashPassword(model.Password);
            foundation.CreatedAt = DateTime.UtcNow;
            _context.Foundation.Add(foundation);
            _context.SaveChanges();
        }

        public Foundation GetById(int id)
        {
            return getUser(id);
        }

        private Foundation getUser(int id)
        {
            var foundation = _context.Foundation.Find(id);
            if (foundation == null) throw new KeyNotFoundException("User not found");
            return foundation;
        }
    }
}
