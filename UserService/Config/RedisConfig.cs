using StackExchange.Redis;

namespace UserService.Config
{
    public static class RedisConfig
    {

        public static void AddRedisConfig(this WebApplicationBuilder builder)
        {
            var redisOptions = new ConfigurationOptions
            {
                EndPoints = { $"{builder.Configuration["Redis:Host"]}:{builder.Configuration["Redis:Port"]}" },
                User = builder.Configuration["Redis:User"],
                Password = builder.Configuration["Redis:Password"],
                AbortOnConnectFail = false,
                AllowAdmin = bool.Parse(Environment.GetEnvironmentVariable("REDIS_ALLOW_ADMIN") ?? "false")
            };

            var redis = ConnectionMultiplexer.Connect(redisOptions);
            builder.Services.AddSingleton<IConnectionMultiplexer>(redis);
        }
    }
}