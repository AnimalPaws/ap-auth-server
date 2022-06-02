using Microsoft.AspNetCore.Builder;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using ap_auth_server.Controllers;
using ap_auth_server.Helpers;
using ap_auth_server.Models;
using ap_auth_server.Services;
using ap_auth_server.Authorization;
using AutoMapper;
using ap_auth_server.Models.Users;
using ap_auth_server.Entities.User;

var builder = WebApplication.CreateBuilder(args);

var configuration = builder.Configuration;

var config = new MapperConfiguration(cfg => {
    cfg.CreateMap<RegisterRequest, User>();
    cfg.CreateMap<User, AuthenticateResponse>();
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
    services.AddControllers();
    services.AddCors();
    services.AddHttpContextAccessor();
    services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

    // Utils
    services.AddScoped<IJwtUtils, JwtUtils>();

    // Interfaces
    services.AddScoped<IUserService, UserService>();

    services.AddSingleton(mapper);

    services.AddAutoMapper(typeof(AutoMapperProfile));

    services.Configure<AppSettings>(configuration.GetSection("AppSettings"));
}

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Global error handler
app.UseMiddleware<ErrorHandlerMiddleware>();

// Custom JWT Middleware de autentificación
app.UseMiddleware<JwtMiddleware>();

app.UseCors(x => x
    .AllowAnyHeader()
    .AllowAnyMethod()
    .AllowAnyOrigin());

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();