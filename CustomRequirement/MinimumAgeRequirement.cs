using Microsoft.AspNetCore.Authorization;

namespace DemoPolicyAuthInWebAPI.CustomRequirement
{
    public class MinimumAgeRequirement(int Age) : IAuthorizationRequirement
    {
    }
}
