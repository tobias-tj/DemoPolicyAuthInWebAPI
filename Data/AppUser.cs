using Microsoft.AspNetCore.Identity;

namespace DemoPolicyAuthInWebAPI.Data
{
    public class AppUser : IdentityUser
    {
        public DateTime DateOfBirth { get; set; }
    }
}
