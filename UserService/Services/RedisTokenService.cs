using StackExchange.Redis;
using UserService.Services.Interfaces;

namespace UserService.Services
{
    public class RedisTokenService : ITokenService
    {
        private readonly IDatabase _redisDb;

        public RedisTokenService(IConnectionMultiplexer redis)
        {
            _redisDb = redis.GetDatabase();
        }

        public async Task StoreTokenAsync(string userId, string token, TimeSpan expiry)
        {
            // Store the token with the user ID as the value
            await _redisDb.StringSetAsync(token, userId, expiry);
        }

        public async Task InvalidateTokenAsync(string token)
        {
            // Delete the token from Redis
            await _redisDb.KeyDeleteAsync(token);
        }

        public async Task<bool> IsTokenValidAsync(string token)
        {
            // Check if the token exists in Redis
            return await _redisDb.KeyExistsAsync(token);
        }
    }
}
