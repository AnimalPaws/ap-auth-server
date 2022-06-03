using ap_auth_server.Entities.Foundation;
using ap_auth_server.Entities.User;
using ap_auth_server.Entities.Veterinary;
using Microsoft.EntityFrameworkCore;

namespace ap_auth_server.Helpers
{
    public class DataContext : DbContext
    {
        protected readonly IConfiguration Configuration;
        public DataContext(IConfiguration configuration, DbContextOptions options) : base (options)
        {
            Configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            // connect to sql server database
            options.UseMySQL(Configuration.GetConnectionString("APDatabase"));
        }

        public DbSet<User> User { get; set; }
        public DbSet<Veterinary> Veterinary { get; set; }
        public DbSet<Foundation> Foundation { get; set; }
    }
}
