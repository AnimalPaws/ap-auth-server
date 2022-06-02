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

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
{
    var services = builder.Services;

    services.AddEndpointsApiExplorer();
    services.AddSwaggerGen();

    //DataContext
    services.AddDbContext<DataContext>(option => option.UseMySQL(builder.Configuration.GetConnectionString("APDatabase")));

    services.AddControllers();
    services.AddCors();
    services.AddHttpContextAccessor();

    //Utils
    services.AddScoped<IJwtUtils, JwtUtils>();

    //Interfaces
    services.AddScoped<IUserService, UserService>();

    services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());
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