// @audit-fixture
// @rule: sql_injection_concat_csharp, unsafe_deserialization_csharp, xxe_injection_csharp,
//        command_injection_csharp, weak_crypto_csharp, weak_random_csharp, ssl_bypass_csharp,
//        xss_raw_html, cors_permissive_csharp, open_redirect_csharp, verbose_exception_csharp,
//        secret_logged_csharp, ldap_injection_csharp, request_validation_disabled,
//        db_logic_controller_csharp, console_write_csharp, catch_all_exception_csharp
// @category: security, architecture, maintenance
// @expected: detected

using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;

namespace Vulnerable.Controllers
{
    [ApiController]
    public class VulnerableController : Controller
    {
        private readonly ILogger<VulnerableController> _logger;
        private readonly DbContext _dbContext;

        // SQL injection par concatenation
        public void FindUser(string username)
        {
            var conn = new SqlConnection("Server=localhost");
            var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + username + "'", conn);
            cmd.ExecuteReader();
        }

        // Deserialization non securisee (BinaryFormatter)
        public object Deserialize(Stream stream)
        {
            var formatter = new BinaryFormatter();
            return formatter.Deserialize(stream);
        }

        // XXE injection (DtdProcessing.Parse)
        public void ParseXml(string xml)
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Parse;
            var reader = XmlReader.Create(new StringReader(xml), settings);
        }

        // Command injection (Process.Start)
        public void RunCommand(string cmd)
        {
            Process.Start(cmd);
        }

        // Weak crypto (MD5)
        public byte[] HashPassword(string password)
        {
            var md5 = MD5.Create();
            return md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        }

        // Weak random pour token
        public string GenerateToken()
        {
            var random = new Random();
            return "token_" + random.Next();
        }

        // SSL bypass
        public void SetupHttp()
        {
            System.Net.ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;
        }

        // XSS via Html.Raw
        public IActionResult ShowComment(string comment)
        {
            ViewBag.Comment = Html.Raw(comment);
            return View();
        }

        // CORS permissive
        public void ConfigureCors()
        {
            // services.AddCors(o => o.AddPolicy("p", b => b.AllowAnyOrigin()));
            var x = "AllowAnyOrigin()";
        }

        // Open redirect
        public IActionResult Login(string returnUrl)
        {
            return Redirect(Request.Query["returnUrl"]);
        }

        // Verbose exception (UseDeveloperExceptionPage)
        public void Configure()
        {
            // app.UseDeveloperExceptionPage();
            var page = "UseDeveloperExceptionPage()";
        }

        // Secret logged
        public void Authenticate(string password)
        {
            _logger.LogInformation("Auth attempt with password: " + password);
        }

        // LDAP injection
        public void SearchUser(string username)
        {
            var searcher = new DirectorySearcher();
            searcher.Filter = "(uid=" + username + ")";
        }

        // Request validation disabled
        [ValidateInput(false)]
        public IActionResult Submit(string data)
        {
            return Ok(data);
        }

        // DB logic in controller
        [HttpGet("/users")]
        public IActionResult GetUsers()
        {
            var users = _dbContext.Set<object>().ToList();
            return Ok(users);
        }

        // Console.WriteLine
        public void DebugMethod()
        {
            Console.WriteLine("Debug: entering method");
        }

        // Generic catch
        public void ProcessData()
        {
            try
            {
                RiskyOperation();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        // Dapper SQL injection
        public object FindUser(string username)
        {
            return connection.Query("SELECT * FROM users WHERE name = '" + username + "'");
        }

        private void RiskyOperation() { }
    }
}
