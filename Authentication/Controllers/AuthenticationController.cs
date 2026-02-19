using Authentication.BusinessLayer.DTO;
using Authentication.BusinessLayer.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;

namespace Authentication.WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthenticationService _authService;
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController(IAuthenticationService authService, ILogger<AuthenticationController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterRequestVM model)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var ipAddress = GetClientIpAddress();
                var userAgent = GetUserAgent();

                var result = await _authService.RegisterAsync(model, ipAddress, userAgent);

                if (result == null)
                    return BadRequest(new { message = "Registration failed" });

                _logger.LogInformation("User registered successfully: {Email}", model.Email);

                return Ok(new
                {
                    message = "Registration successful",
                    data = result
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration");
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequestVM model)
        {
            try
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var ipAddress = GetClientIpAddress();
                var userAgent = GetUserAgent();

                var result = await _authService.LoginAsync(model, ipAddress, userAgent);
                 if(!result.Success)
                {
                    if(result.IsRateLimited || result.IsLockedOut)
                    {
                        return StatusCode(429, new { message = result.ErrorMessage });
                    }

                    return Unauthorized(new {message = result.ErrorMessage , remainingLoginAttempts = result.RemainingLoginAttempts});
                }

                _logger.LogInformation("User logged in: {Email}", model.Email);

                /* if (await _authService.LoginAsync(model, ipAddress, userAgent) == null)
                     return BadRequest(new { message = "Invalid credentials" });*/

                if (await _authService.IsUserLockedOutAsync(model.Email))
                    return StatusCode(429, new { message = "Too many login attempts. Try again later." });

                // Set refresh token cookie
                SetRefreshTokenCookie(result.RefreshToken, result.RefreshTokenExpiry);

                return Ok(new
                {
                    message = "Login successful",
                    data = new
                    {
                        accessToken = result.AccessToken,
                        accessTokenExpires = result.AccessTokenExpiry,
                        user = result.User
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            try
            {
                var refreshToken = Request.Cookies["refreshToken"];

                if (string.IsNullOrEmpty(refreshToken))
                    return BadRequest(new { message = "Refresh token is missing" });

                var ipAddress = GetClientIpAddress();
                var userAgent = GetUserAgent();

                var result = await _authService.RefreshTokenAsync(refreshToken, ipAddress, userAgent);

                if (result == null)
                    return BadRequest(new { message = "Invalid refresh token" });

                // Set new refresh token cookie
                SetRefreshTokenCookie(result.RefreshToken, result.RefreshTokenExpiry);

                return Ok(new
                {
                    message = "Token refreshed",
                    data = new
                    {
                        accessToken = result.AccessToken,
                        accessTokenExpires = result.AccessTokenExpiry,
                        user = result.User
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token refresh");
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        [HttpPost("revoke-token")]
        [Authorize]
        public async Task<IActionResult> RevokeToken()
        {
            try
            {
                var refreshToken = Request.Cookies["refreshToken"];

                if (string.IsNullOrEmpty(refreshToken))
                    return BadRequest(new { message = "Refresh token is missing" });

                var ipAddress = GetClientIpAddress();
                var result = await _authService.RevokeTokenAsync(refreshToken);

                if (!result)
                    return BadRequest(new { message = "Token revoke failed" });

                // Clear refresh token cookie
                Response.Cookies.Delete("refreshToken");

                return Ok(new { message = "Token revoked successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token revoke");
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var refreshToken = HttpContext.Request.Cookies["refreshToken"];

                if (!string.IsNullOrEmpty(refreshToken))
                {
                    var ipAddress = GetClientIpAddress();
                    await _authService.RevokeTokenAsync(refreshToken);
                }

                // Clear refresh token cookie
                Response.Cookies.Delete("refreshToken");

                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                _logger.LogInformation("User logged out: {UserId}", userId);

                return Ok(new { message = "Logout successful" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout");
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        [HttpGet("me")]
        [Authorize]
        public IActionResult GetCurrentUser()
        {
            try
            {
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                var email = User.FindFirstValue(ClaimTypes.Email);
                var firstName = User.FindFirstValue("first_name");
                var lastName = User.FindFirstValue("last_name");

                return Ok(new
                {
                    message = "User details fetched successfully",
                    data = new
                    {
                        id = userId,
                        email = email,
                        firstName = firstName,
                        lastName = lastName
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching current user");
                return StatusCode(500, new { message = "Internal server error" });
            }
        }

        private string GetClientIpAddress()
        {
            var ipAddress = HttpContext.Request.Headers["X-Forwarded-For"].ToString();
            if (!string.IsNullOrEmpty(ipAddress))
            {
                return ipAddress.Split(',')[0];
            }
            ipAddress = HttpContext.Request.Headers["X-Real-IP"].ToString();
            if (!string.IsNullOrEmpty(ipAddress))
            {
                return ipAddress;
            }

           return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            
        }

        private string GetUserAgent()
        {
            return HttpContext.Request.Headers["User-Agent"].ToString();
        }

        private void SetRefreshTokenCookie(string token, DateTime expires)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Expires = expires,
                Path = "/",
                IsEssential = true
            };

            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }
    }
}
