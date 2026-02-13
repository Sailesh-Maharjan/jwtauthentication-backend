using Authentication.BusinessLayer.Interfaces;
using Authentication.BusinessLayer.Services;
using Authentication.DataAccessLayer.AppDbContext;
using Authentication.DataAccessLayer.Configuration;
using Authentication.WebApi.Middleware;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using StackExchange.Redis;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Default: appsettings.json
// Automatically override with environment variables
builder.Configuration.AddEnvironmentVariables();

// Add services to the container.
builder.Services.AddControllers();

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File("logs/log-.txt", rollingInterval: RollingInterval.Day) //  dash(-) on logs/log-.txt acts as placeholder for intervals
    .CreateLogger();

builder.Host.UseSerilog();

// DB configuration with postgresql
builder.Services.AddDbContext<ApplicationDbContext>(options =>
   options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultSqlConnection"),
   b => b.MigrationsAssembly("Authentication.DataAccessLayer"))
   .UseSnakeCaseNamingConvention() // keeping snake_case globally
   );


// redis cofiguration
var redisSettings = builder.Configuration.GetSection("RedisSettings").Get<RedisSettings>();

if (redisSettings is null || string.IsNullOrWhiteSpace(redisSettings.ConnectionString))
{
    throw new InvalidOperationException("Redis configuration is missing or invalid.");
}

builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
{
    return ConnectionMultiplexer.Connect(redisSettings.ConnectionString);

    //var options = ConfigurationOptions.Parse(redisSettings.ConnectionString);
    //options.AbortOnConnectFail = false; // important for cloud Redis
    //return ConnectionMultiplexer.Connect(options);
});

//builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
//{
//    var options = new ConfigurationOptions
//    {
//        EndPoints = { { "redis-11373.c258.us-east-1-4.ec2.cloud.redislabs.com", 11373 } },
//        User = "default",
//        Password = "x3tlJydU3pCEdr58008M0ZojLdo3iCiI",
//        Ssl = false,
//        AbortOnConnectFail = false,
//        SslProtocols = SslProtocols.Tls12,
//        ConnectRetry = 3,
//        KeepAlive = 180
//    };


//    return ConnectionMultiplexer.Connect(options);
//});


// Binding settings from appsettings.json
builder.Services.Configure<JwtSettings>(
    builder.Configuration.GetSection("JwtSettings"));

builder.Services.Configure<RedisSettings>(
    builder.Configuration.GetSection("RedisSettings"));

builder.Services.Configure<RateLimitingSettings>(
    builder.Configuration.GetSection("RateLimitingSettings"));

//injecting DI
builder.Services.AddScoped<IAuthenticationService,AuthenticationService>();
builder.Services.AddSingleton<IRedisService, RedisService>();
builder.Services.AddScoped<ITokenService, TokenService>();


//JWT Authentication Configuration
var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();
if (jwtSettings == null)
{
    throw new Exception("JwtSettings section is missing in appsettings.json");
}

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secretkey)),
        ValidateIssuer = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidateAudience = true,
        ValidAudience = jwtSettings.Audience,
        ValidateLifetime = true, // reject expired token after as well as nbf(not before)
        ClockSkew = TimeSpan.Zero // no extra time
    };

    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            Log.Warning("JWT authentication failed: {0}", context.Exception.Message);
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            Log.Information("JWT token validated for: {0}", context.Principal?.Identity?.Name);
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization();

// Configure CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigin", policy =>
    {
        policy.WithOrigins("http://127.0.0.1:5500", "http://localhost:5500", "https://127.0.0.1:5500", "https://localhost:5500") // replace with your allowed origin
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(x =>
{
    x.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authentication",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    x.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id ="Bearer"
                }
            },
                Array.Empty<string>()
        }
    });   
});

builder.Services.AddHealthChecks().AddDbContextCheck<ApplicationDbContext>()
                                  .AddRedis(builder.Configuration["RedisSettings:ConnectionString"]);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseCors("AllowSpecificOrigin");

app.UseMiddleware<SecurityMiddleware>();
app.UseMiddleware<RateLimitMiddleware>();


app.UseAuthentication();    
app.UseAuthorization();

app.MapControllers();

app.MapHealthChecks("/health");

app.Run();
