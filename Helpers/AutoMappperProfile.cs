using ap_auth_server.Entities.User;
using ap_auth_server.Models.Foundation;
using AutoMapper;

namespace ap_auth_server.Helpers
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            // User -> AuthenticateResponse
            this.CreateMap<User, FoundationAuthenticateResponse>().ReverseMap();

            // RegisterRequest -> User
            this.CreateMap<FoundationRegisterRequest, User>().ReverseMap();

            // UpdateRequest -> User
            this.CreateMap<FoundationUpdateRequest, User>()
                .ForAllMembers(x => x.Condition(
                    (src, dest, prop) =>
                    {
                        // ignore null & empty string properties
                        if (prop == null) return false;
                        if (prop.GetType() == typeof(string) && string.IsNullOrEmpty((string)prop)) return false;

                        return true;
                    }
                ));
        }
    }
}
