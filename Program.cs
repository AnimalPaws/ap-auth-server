using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ap_auth_server.Helpers;
using ap_auth_server.Services;
using ap_auth_server.Authorization;
using AutoMapper;
using ap_auth_server.Models.Users;
using ap_auth_server.Models.Foundation;
using ap_auth_server.Models.Veterinary;
using ap_auth_server.Entities.User;
using ap_auth_server.Entities.Foundation;
using ap_auth_server.Entities.Veterinary;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

var configuration = builder.Configuration;

var config = new MapperConfiguration(cfg => {
    cfg.CreateMap<UserRegisterRequest, User>();
    cfg.CreateMap<User, UserAuthenticateResponse>();
    cfg.CreateMap<FoundationRegisterRequest, Foundation>();
    cfg.CreateMap<Foundation, UserAuthenticateResponse>();
    cfg.CreateMap<VeterinaryRegisterRequest, Veterinary>();
    cfg.CreateMap<Veterinary, VeterinaryAuthenticateResponse>();
});

IMapper mapper = config.CreateMapper();


// Add services to the container.
{
    var services = builder.Services;

    services.AddEndpointsApiExplorer();
    services.AddSwaggerGen();


    // DataContext
    services.AddDbContext<DataContext>(option => option.UseMySQL(builder.Configuration.GetConnectionString("APDatabase")));

    // Controllers and cors policies
    services.AddControllers().AddJsonOptions(x =>
    {
        // serialize enums as strings in api responses (e.g. Role)
        x.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    });
    services.AddCors();
    services.AddHttpContextAccessor();
    services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

    // Utils
    services.AddScoped<IJwtUtils, JwtUtils>();

    // Interfaces
    services.AddScoped<IUserService, UserService>();
    services.AddScoped<IFoundationService, FoundationService>();
    services.AddScoped<IVeterinaryService, VeterinaryService>();
    services.AddScoped<IEmailService, EmailService>();

    // AutoMapper
    services.AddSingleton(mapper);
    services.AddAutoMapper(typeof(AutoMapperProfile));

    // AppSettings configuration
    services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));
}

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(x => x.SwaggerEndpoint("/swagger/v1/swagger.json", "AnimalPaws Auth Server"));
}

// Global error handler
app.UseMiddleware<ErrorHandlerMiddleware>();

// Custom JWT Middleware de autentificación
app.UseMiddleware<JwtMiddleware>();

app.UseCors(x => x
        .SetIsOriginAllowed(origin => true)
        .AllowAnyMethod()
        .AllowAnyHeader()
        .AllowCredentials());

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();