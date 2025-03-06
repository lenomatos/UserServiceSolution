using StackExchange.Redis;
using UserService.Services.Interfaces;

namespace UserService.Services
{
    public class RedisTokenService : ITokenService
    {
        private readonly IDatabase _userTokensDb; // Database for user token keys (e.g., sorted sets)
        private readonly IDatabase _tokensDb;     // Database for actual tokens (e.g., key-value pairs)
        private const int MaxActiveTokensPerUser = 2; // Maximum allowed active tokens per user

        public RedisTokenService(IConnectionMultiplexer redis)
        {
            _userTokensDb = redis.GetDatabase(0); // Use Database 0 for user token keys
            _tokensDb = redis.GetDatabase(1);    // Use Database 1 for actual tokens
        }

        public async Task StoreTokenAsync(string userId, string token, TimeSpan expiry)
        {
            try
            {
                var userTokensKey = $"user:{userId}:tokens";

                // Get the current timestamp
                var timestamp = DateTime.UtcNow.Ticks;

                // Add the token to the sorted set in Database 0
                await _userTokensDb.SortedSetAddAsync(userTokensKey, token, timestamp);

                // Set expiry for the sorted set in Database 0
                await _userTokensDb.KeyExpireAsync(userTokensKey, expiry);

                // Store the token in Database 1 with the user ID as the value
                await _tokensDb.StringSetAsync(token, userId, expiry);

                // Enforce the maximum number of active tokens
                var activeTokensCount = await _userTokensDb.SortedSetLengthAsync(userTokensKey);
                if (activeTokensCount > MaxActiveTokensPerUser)
                {
                    // Get the oldest tokens (those with the smallest scores)
                    var oldestTokens = await _userTokensDb.SortedSetRangeByScoreAsync(
                        userTokensKey,
                        order: Order.Ascending,
                        take: activeTokensCount - MaxActiveTokensPerUser
                    );

                    // Remove the oldest tokens from the sorted set in Database 0
                    await _userTokensDb.SortedSetRemoveAsync(userTokensKey, oldestTokens);

                    // Invalidate the removed tokens by deleting their keys in Database 1
                    foreach (var oldToken in oldestTokens)
                    {
                        await _tokensDb.KeyDeleteAsync(oldToken.ToString()); // Use the token as the key
                    }
                }

            }
            catch (Exception ex)
            {
                throw; // Re-throw or handle the exception
            }
        }

        public async Task InvalidateTokenAsync(string token)
        {
            // Get the user ID associated with the token from Database 1
            var userId = await _tokensDb.StringGetAsync(token);
            if (!userId.IsNullOrEmpty)
            {
                // Remove the token from the user's active tokens set in Database 0
                var userTokensKey = $"user:{userId}:tokens";
                await _userTokensDb.SetRemoveAsync(userTokensKey, token);
            }

            // Delete the token from Database 1
            await _tokensDb.KeyDeleteAsync(token);
        }

        public async Task<bool> IsTokenValidAsync(string token)
        {
            // Check if the token exists in Database 1
            return await _tokensDb.KeyExistsAsync(token);
        }

        public async Task<bool> CanAddNewLogin(string userId)
        {
            return MaxActiveTokensPerUser == await GetActiveTokenCountAsync(userId);
        }
        public async Task<int> GetActiveTokenCountAsync(string userId)
        {
            // Get the number of active tokens for the user from Database 0
            var userTokensKey = $"user:{userId}:tokens";
            return (int)await _userTokensDb.SortedSetLengthAsync(userTokensKey);
        }
    }
}