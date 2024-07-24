using DemoPolicyAuthInWebAPI.CustomRequirement;
using DemoPolicyAuthInWebAPI.Data;
using DemoPolicyAuthInWebAPI.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddDbContext<AppDBContext>(o => {
    o.UseSqlServer(builder.Configuration.GetConnectionString("Default"));
});

builder.Services.AddIdentity<AppUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDBContext>()
    .AddSignInManager()
    .AddRoles<IdentityRole>();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidateLifetime = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!))
    };
});

builder.Services.AddSwaggerGen(swagger =>
{
    swagger.SwaggerDoc("v1", new OpenApiInfo { Version = "v1" });
    swagger.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header
    });
    swagger.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            }, Array.Empty<string>()
        }
    });
});

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("AdminManagerUserPolicy", o =>
    {
        o.RequireAuthenticatedUser();
        o.RequireRole("admin", "manager", "user");
    })
    .AddPolicy("AdminManagerPolicy", o =>
    {
        o.RequireAuthenticatedUser();
        o.RequireRole("admin", "manager");
    })
    .AddPolicy("AdminUserPolicy", o =>
    {
        o.RequireAuthenticatedUser();
        o.RequireRole("admin", "user");
        o.Requirements.Add(new MinimumAgeRequirement(18));
    });

builder.Services.AddSingleton<IAuthorizationHandler, MinimumAgeHandler>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/account/create",
    async (RegisterModel model, UserManager<AppUser> userManager) =>
    {
        var user = await userManager.FindByEmailAsync(model.Email);
        if (user != null) return Results.BadRequest(false);

        AppUser newUser = new()
        {
            UserName = model.Email,
            Email = model.Email,
            DateOfBirth = model.DateOfBirth
        };
        var result = await userManager.CreateAsync(newUser, model.Password);

        if (!result.Succeeded)
            return Results.BadRequest(false);

        var userClaims = new Claim[]
        {
            new Claim(ClaimTypes.Email, model.Email),
            new Claim(ClaimTypes.Role, model.Role),
            new Claim(ClaimTypes.DateOfBirth, model.DateOfBirth.ToString("yyyy-MM-dd"))
        };
        await userManager.AddClaimsAsync(newUser, userClaims);
        return Results.Ok(true);
    });

app.MapPost("account/login", async (string email, string password, UserManager<AppUser> userManager,
    SignInManager<AppUser> signInManager, IConfiguration config) =>
{
    var user = await userManager.FindByEmailAsync(email);
    if (user == null) return Results.NotFound();

    var result = await signInManager.CheckPasswordSignInAsync(user!, password, false);
    if (!result.Succeeded) return Results.BadRequest(null);

    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: config["Jwt:Issuer"],
        audience: config["Jwt:Audience"],
        claims: await userManager.GetClaimsAsync(user),
        expires: DateTime.Now.AddDays(1),
        signingCredentials: credentials
    );

    return Results.Ok(new JwtSecurityTokenHandler().WriteToken(token));
});

app.MapGet("/list",
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Policy = "AdminManagerPolicy")]
() => Results.Ok("Admin and Manager only can have access"));

app.MapGet("/single",
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Policy = "AdminUserPolicy")]
() => Results.Ok("Admin and User Only"));

app.MapGet("/home",
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Policy = "AdminManagerUserPolicy")]
() => Results.Ok("Hello, welcome home everyone"));

app.Run();
