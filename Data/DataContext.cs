using ap_auth_server.Models;
using Microsoft.EntityFrameworkCore;
namespace ap_auth_server.Data
{
    public class DataContext : DbContext
    {
        // Se instancia la configuración de la DB
        protected readonly IConfiguration Configuration;

        // Se establece la configuración para el entorno de la DB
        public DataContext(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            //Conexión a MySql con los valores de app settings
            var connectionString = Configuration.GetConnectionString("Database");
            options.UseMySQL(connectionString);
        }
    }
}
