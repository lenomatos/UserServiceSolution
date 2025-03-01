using Microsoft.AspNetCore.Identity;
using UserService.Data;
using UserService.Models;
using UserService.Services.Interfaces;
using UserService.Services;
using Microsoft.EntityFrameworkCore;

namespace UserService.Config
{
    public static class DependencyInjectionConfig
    {
        public static void RegisterServices(this WebApplicationBuilder builder)
        {
            builder.Services.AddScoped<ITokenService, RedisTokenService>();

            builder.Services.AddDbContext<UserDbContext>(options =>
                options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            builder.Services.AddIdentity<User, IdentityRole>()
                .AddEntityFrameworkStores<UserDbContext>()
                .AddDefaultTokenProviders();

            builder.Services.AddControllers();
        }
    }
}
