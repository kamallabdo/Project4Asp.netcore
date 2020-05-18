using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Exo3_1.models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Exo3_1.Controllers
{
    [Route("api/[controller]")]
    [EnableCors("MyPolicy")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        // GET: api/Login
        private readonly IConfiguration _config;

        public LoginController(IConfiguration config)
        {
            _config = config;
        }

        private readonly IEnumerable<User> _users = new List<User>
        {
            new User {id=1,Username="kamal",Password="123",Role="adminstrator"},
            new User {id=2,Username="Abdo",Password="123",Role="user"}

        };

        private String GenerateJSONWebToken(User userInfo)
        {
            var user = _users.Where(x => x.Username == userInfo.Username && x.Password == userInfo.Password).SingleOrDefault();
            if (user == null)
            {
                return null;
            }
            var signingKey = Convert.FromBase64String(_config["Jwt:key"]);
            var expiryDuration = int.Parse(_config["Jwt:ExpiryDuration"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = null,
                Audience = null,
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMinutes(expiryDuration),
                Subject = new ClaimsIdentity(new List<Claim>
                {
                    new Claim("userid",user.id.ToString()),
                    new Claim("roles",user.Role),
                    new Claim("Username",user.Username.ToString())
                }),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(signingKey), SecurityAlgorithms.HmacSha256Signature)
            };
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = jwtTokenHandler.CreateJwtSecurityToken(tokenDescriptor);
            var token = jwtTokenHandler.WriteToken(jwtToken);
            return token;
        }

        [HttpPost]
        public IActionResult Post([FromBody] User user)
        {
            var jwtToken = GenerateJSONWebToken(user);
            if (jwtToken == null)
            {
                return Unauthorized();
            }
            return Ok(jwtToken);
        }

        [HttpGet]
        [Authorize]
        public IActionResult Get()
        {
            var currentUser = HttpContext.User.Claims.Where(x => x.Type == "userid").SingleOrDefault();
            return Ok($"utilisateur connecte a un id"+ currentUser.Value);
        }
        [HttpGet]
        [Route("gestion")]
        [Authorize(Roles = "adminstrator")]
        public IActionResult Gestion()
        {
            var currentUser = HttpContext.User.Claims.Where(x => x.Type == "userid").SingleOrDefault();
            return Ok($"utilisateur connecte a un id" + currentUser.Value);
           
        }
        
    }
}
