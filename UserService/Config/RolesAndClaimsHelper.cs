using System.ComponentModel;

namespace UserService.Config
{
    public static class RolesAndClaimsHelper
    {
        public enum Roles
        {
            [Description("Admin")]
            Admin,
            [Description("Seller")]
            Seller,
            [Description("Customer")]
            Customer
        }

        public enum Claims
        {
            [Description("Email")]
            Email,
            [Description("PhoneNumber")]
            PhoneNumber,
            [Description("IsVerified")]
            IsVerified,
            [Description("Read")]
            Read,
            [Description("Write")]
            Write,
            [Description("Delete")]
            Delete
        }

        public enum Policies
        {
            [Description("AdminOnly")]
            AdminOnly,
            [Description("SellerOnly")]
            SellerOnly,
            [Description("CanUpdate")]
            CanUpdate,
            [Description("IsVerifiedCustomer")]
            IsVerifiedCustomer
        }

        public static string GetRoleOrClaimOrPolice<T>(T enumValue) where T : Enum
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