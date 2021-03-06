using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Linq;
using System.Threading.Tasks;
using ap_auth_server.Services;
using ap_auth_server.Helpers;

namespace ap_auth_server.Authorization
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly AppSettings _appSettings;

        public JwtMiddleware(RequestDelegate next, IOptions<AppSettings> appSettings)
        {
            _next = next;
            _appSettings = appSettings.Value;
        }

        public async Task Invoke(HttpContext context, DataContext dataContext, IJwtUtils jwtUtils)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            var id = jwtUtils.ValidateToken(token);
            if (id != null)
            {
                // attach user to context on successful jwt validation
                context.Items["User"] = dataContext.User.FindAsync(id.Value);
            }

            await _next(context);
        }
    }
}