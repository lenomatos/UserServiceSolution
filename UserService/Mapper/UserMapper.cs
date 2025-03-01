using Riok.Mapperly.Abstractions;
using UserService.DTOs;
using UserService.Models;

namespace UserService.Mapper
{
    [Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
    public partial class UserMapper
    {
        public partial UserProfileDto MapToDto(User user);
    }
}
