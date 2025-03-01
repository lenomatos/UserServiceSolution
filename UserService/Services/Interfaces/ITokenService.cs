namespace UserService.Services.Interfaces
{
    public interface ITokenService
    {
        Task StoreTokenAsync(string userId, string token, TimeSpan expiry);
        Task InvalidateTokenAsync(string token);
        Task<bool> IsTokenValidAsync(string token);
    }
}
