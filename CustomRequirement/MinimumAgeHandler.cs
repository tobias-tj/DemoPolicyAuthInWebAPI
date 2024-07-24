using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace DemoPolicyAuthInWebAPI.CustomRequirement
{
    public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MinimumAgeRequirement requirement)
        {
            if(!context.User.Identity.IsAuthenticated)
                return Task.CompletedTask;
            if(!context.User.HasClaim(c => c.Type == ClaimTypes.DateOfBirth))
                return Task.CompletedTask;

            var date = context.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.DateOfBirth)!.Value;
            DateTime _date = DateTime.Parse(date);
            double age = DateTime.Now.Subtract(_date).TotalDays / 360;
            if (age >= 18)
                context.Succeed(requirement);

            return Task.CompletedTask;

        }
    }
}
