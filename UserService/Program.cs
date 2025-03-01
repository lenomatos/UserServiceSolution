using DotNetEnv;
using UserService.Config;

var builder = WebApplication.CreateBuilder(args);

Env.Load();

builder.EnvironmentConfig();
builder.AddRedisConfig();
builder.RegisterServices();
builder.AddJwtAuthenticationConfig();

builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();

builder.AddSwaggerGenConfig();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers().RequireAuthorization();

app.Run();