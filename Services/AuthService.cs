using ap_auth_server.Authorization;
using ap_auth_server.Helpers;
using ap_auth_server.Models;
using AutoMapper;

namespace ap_auth_server.Services
{
    public interface IAuthService
    {
        void Authenticate(AuthenticateRequest model);
    }
    public class AuthService
    {
        private DataContext _dataContext;
        private IJwtUtils _jwtUtils;
        private IMapper _mapper;

        public AuthService(
            DataContext context,
            IJwtUtils jwtutils,
            IMapper mapper)
        {
            _dataContext = context;
            _jwtUtils = jwtutils;
            _mapper = mapper;
        }
    }

}
