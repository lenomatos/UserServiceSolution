using DotNetEnv;
using UserService.Config;

var builder = WebApplication.CreateBuilder(args);

Env.Load();

builder.EnvironmentConfig();
builder.AddRedisConfig();
builder.RegisterServices();
builder.AddJwtAuthenticationConfig();


builder.AddAuthorizationAndPolicyConfig();

builder.Services.AddEndpointsApiExplorer();

builder.AddSwaggerGenConfig();

var app = builder.Build();

// Seed roles and claims into the database
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    await SeedRolesAndClaimsConfig.SeedRolesAndClaims(services);
}


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
