using AutoMapper;
using BCryptNet = BCrypt.Net.BCrypt;
using ap_auth_server.Helpers;
using ap_auth_server.Authorization;
using ap_auth_server.Models.Veterinary;
using ap_auth_server.Entities.Veterinary;
using ap_auth_server.Models;

namespace ap_auth_server.Services
{
    public interface IVeterinaryService
    {
        VeterinaryAuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
        void Register(VeterinaryRegisterRequest model);
        /*IEnumerable<User> GetAll();*/
        Veterinary GetById(int id);
        /*void Update(int id, UpdateRequest model);
        void Delete(int id);*/
    }
    public class VeterinaryService : IVeterinaryService
    {
        private DataContext _context;
        private IJwtUtils _jwtUtils;
        private readonly IMapper _mapper;

        public VeterinaryService(
            DataContext context,
            IJwtUtils jwtUtils,
            IMapper mapper)
        {
            _context = context;
            _jwtUtils = jwtUtils;
            _mapper = mapper;
        }

        public VeterinaryAuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
        {
            var veterinary = _context.Veterinary.SingleOrDefault(x => x.Email == model.Username);

            if (model.Username != veterinary.Email)
            {
                throw new AppException("That account doesn't exists");
            }

            if (veterinary == null || !BCryptNet.Verify(model.Password, veterinary.Password))
            {
                throw new AppException("Invalid credentials, please try again");
            }

            var response = _mapper.Map<VeterinaryAuthenticateResponse>(veterinary);
            response.Token = _jwtUtils.GenerateToken(veterinary);
            return response;
        }

        public void Register(VeterinaryRegisterRequest model)
        {
            if (_context.User.Any(x => x.Email == model.Email) ||
                _context.Foundation.Any(x => x.Email == model.Email) ||
                _context.Veterinary.Any(x => x.Email == model.Email))
            {
                throw new AppException("An account with that email address already exists.");
            }

            if (_context.Veterinary.Any(x => x.Name == model.Name))
            {
                throw new AppException("Name {0} is already taken", model.Name);
            }

            var veterinary = _mapper.Map<Veterinary>(model);
            veterinary.Password = BCryptNet.HashPassword(model.Password);
            veterinary.Created_At = DateTime.UtcNow;
            _context.Veterinary.Add(veterinary);
            _context.SaveChanges();
        }

        public Veterinary GetById(int id)
        {
            return getUser(id);
        }

        private Veterinary getUser(int id)
        {
            var veterinary = _context.Veterinary.Find(id);
            if (veterinary == null) throw new KeyNotFoundException("User not found");
            return veterinary;
        }
    }
}
