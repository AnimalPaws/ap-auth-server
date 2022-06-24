using ap_auth_server.Entities.Foundations;
using ap_auth_server.Entities.Users;
using ap_auth_server.Entities.Veterinaries;
using Microsoft.AspNetCore.Mvc;

namespace ap_auth_server.Controllers
{
    [Controller]
    public abstract class BaseController : ControllerBase
    {
        // returns the current authenticated account (null if not logged in)
        public User User => (User)HttpContext.Items["User"];
        public Foundation Foundation => (Foundation)HttpContext.Items["Foundation"];
        public Veterinary Veterinary => (Veterinary)HttpContext.Items["Veterinary"];
    }
}
