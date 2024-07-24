namespace DemoPolicyAuthInWebAPI.Models
{
    public record RegisterModel(string Email, string Role, DateTime DateOfBirth, string Password);

}
