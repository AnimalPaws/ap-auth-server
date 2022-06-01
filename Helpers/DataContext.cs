using Microsoft.EntityFrameworkCore;

namespace ap_auth_server.Helpers
{
    public class DataContext : DbContext
    {
        protected readonly IConfiguration Configuration;

        public DataContext(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            // connect to sql server database
            options.UseMySQL(Configuration.GetConnectionString("APDatabase"));
        }

        public DbSet<User> Users { get; set; }
    }
}
