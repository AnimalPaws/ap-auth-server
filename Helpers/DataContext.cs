using ap_auth_server.Entities;
using ap_auth_server.Entities.Foundations;
using ap_auth_server.Entities.Users;
using ap_auth_server.Entities.Veterinaries;
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
        public DbSet<UserProfile> User_Profile { get; set; }
        public DbSet<Veterinary> Veterinary { get; set; }
        public DbSet<VeterinaryProfile> Veterinary_Profile { get; set; }
        public DbSet<Foundation> Foundation { get; set; }
        public DbSet<FoundationProfile> Foundation_Profile { get; set; }
        public DbSet<RefreshToken> RefreshToken { get; set; }
    }
}
