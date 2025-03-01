using System.ComponentModel;

namespace UserService.Config
{
    public static class RolesAndClaimsHelper
    {
        public enum Roles
        {
            Admin,
            Seller,
            Customer
        }

        public enum Claims
        {
            Email,
            PhoneNumber,
            IsVerified
        }

        public enum Policies
        {
            IsVerifiedCustomer
        }
        public static string GetRoleOrClaim<T>(T enumValue) where T : Enum
        {
            var enumType = typeof(T);
            var enumName = Enum.GetName(enumType, enumValue);
            var enumMember = enumType.GetMember(enumName);

            if (enumMember.Length > 0)
            {
                var attributes = enumMember[0].GetCustomAttributes(typeof(DescriptionAttribute), false);
                if (attributes.Length > 0)
                {
                    return ((DescriptionAttribute)attributes[0]).Description;
                }
            }

            return enumName;
        }
    }
}
