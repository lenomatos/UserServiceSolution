namespace UserService.Config
{
    public static class EnvironmentConfigHelper
    {
        public static void EnvironmentConfig(this WebApplicationBuilder builder)
        {
            // Get environment variables
            var jwtKey = Environment.GetEnvironmentVariable("JWT_KEY");
            var jwtIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER");
            var jwtAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE");
            var dbConnection = Environment.GetEnvironmentVariable("DB_CONNECTION");
            var redisHost = Environment.GetEnvironmentVariable("REDIS_HOST");
            var redisPort = Environment.GetEnvironmentVariable("REDIS_PORT");
            var redisUser = Environment.GetEnvironmentVariable("REDIS_USER");
            var redisPassword = Environment.GetEnvironmentVariable("REDIS_PASSWORD");
            var redisAllowAdmin = bool.Parse(Environment.GetEnvironmentVariable("REDIS_ALLOW_ADMIN") ?? "false");

            // Update configuration with environment variables
            builder.Configuration["Jwt:Key"] = jwtKey;
            builder.Configuration["Jwt:Issuer"] = jwtIssuer;
            builder.Configuration["Jwt:Audience"] = jwtAudience;
            builder.Configuration["ConnectionStrings:DefaultConnection"] = dbConnection;
            builder.Configuration["Redis:Host"] = redisHost;
            builder.Configuration["Redis:Port"] = redisPort;
            builder.Configuration["Redis:User"] = redisUser;
            builder.Configuration["Redis:Password"] = redisPassword;
        }
    }
}
