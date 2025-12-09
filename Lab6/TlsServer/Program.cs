// TlsServer/Program.cs
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// logger
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddFile("server_logs.txt"); // we'll add simple file logger below if provider missing

// Kestrel HTTPS config: use server.pfx in project folder
var pfxPath = Path.Combine(AppContext.BaseDirectory, "server.pfx");
var pfxPassword = "PfxPassword123!"; // якщо ти міняла пароль при експорті - поміняй тут

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(5001, listen =>
    {
        listen.UseHttps(pfxPath, pfxPassword);
    });
});

var app = builder.Build();

// Simple file logger helper (if not present)
static void AppendLog(string line)
{
    try { File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "server_events.log"), line + Environment.NewLine); } catch { }
}

AppendLog($"START {DateTime.UtcNow:o} | Server starting on https://localhost:5001");

// Simple in-memory user store persisted to users.json
var usersFile = Path.Combine(AppContext.BaseDirectory, "users.json");
Dictionary<string, UserRecord> users;
if (File.Exists(usersFile))
{
    users = JsonSerializer.Deserialize<Dictionary<string, UserRecord>>(File.ReadAllText(usersFile)) ?? new();
}
else
{
    users = new();
    // create default user testuser / Password123!
    var defaultUser = CreateUserRecord("testuser", "Password123!");
    users[defaultUser.Username] = defaultUser;
    File.WriteAllText(usersFile, JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true }));
    AppendLog($"{DateTime.UtcNow:o} | Created default user testuser");
}

// In-memory token store: token -> (username, expiry)
var tokens = new Dictionary<string, (string username, DateTime expiry)>();

app.MapPost("/login", async (HttpContext ctx) =>
{
    var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    try
    {
        var req = await JsonSerializer.DeserializeAsync<LoginRequest>(ctx.Request.Body);
        if (req == null || string.IsNullOrEmpty(req.Username) || string.IsNullOrEmpty(req.Password))
        {
            ctx.Response.StatusCode = 400;
            await ctx.Response.WriteAsync("Bad request");
            AppendLog($"{DateTime.UtcNow:o} | {ip} | login | - | FAIL | 400");
            return;
        }

        if (!users.TryGetValue(req.Username, out var record))
        {
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync("Invalid credentials");
            AppendLog($"{DateTime.UtcNow:o} | {ip} | login | {req.Username} | FAIL | user not found");
            return;
        }

        if (!VerifyPassword(req.Password, record))
        {
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync("Invalid credentials");
            AppendLog($"{DateTime.UtcNow:o} | {ip} | login | {req.Username} | FAIL | bad password");
            return;
        }

        var token = Guid.NewGuid().ToString("D");
        var expiry = DateTime.UtcNow.AddMinutes(30);
        tokens[token] = (req.Username, expiry);

        var resp = new { token, expires = expiry };
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(JsonSerializer.Serialize(resp));
        AppendLog($"{DateTime.UtcNow:o} | {ip} | login | {req.Username} | SUCCESS | token issued");
    }
    catch (Exception ex)
    {
        ctx.Response.StatusCode = 500;
        await ctx.Response.WriteAsync("Server error");
        AppendLog($"{DateTime.UtcNow:o} | {ip} | login | - | ERROR | {ex.Message}");
    }
});

app.MapPost("/upload", async (HttpContext ctx) =>
{
    var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    try
    {
        // Authorization header: Bearer <token>
        if (!ctx.Request.Headers.TryGetValue("Authorization", out var auth) || string.IsNullOrEmpty(auth))
        {
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync("Missing Authorization");
            AppendLog($"{DateTime.UtcNow:o} | {ip} | upload | - | FAIL | missing auth");
            return;
        }
        var authStr = auth.ToString();
        if (!authStr.StartsWith("Bearer ")) { ctx.Response.StatusCode = 401; await ctx.Response.WriteAsync("Invalid auth"); AppendLog($"{DateTime.UtcNow:o} | {ip} | upload | - | FAIL | invalid auth"); return; }
        var token = authStr.Substring("Bearer ".Length).Trim();
        if (!tokens.TryGetValue(token, out var tokenInfo) || tokenInfo.expiry < DateTime.UtcNow)
        {
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync("Invalid or expired token");
            AppendLog($"{DateTime.UtcNow:o} | {ip} | upload | - | FAIL | invalid/expired token");
            return;
        }

        // Expect multipart/form-data with file field "file"
        if (!ctx.Request.HasFormContentType)
        {
            ctx.Response.StatusCode = 400;
            await ctx.Response.WriteAsync("Expected form-data");
            AppendLog($"{DateTime.UtcNow:o} | {ip} | upload | {tokenInfo.username} | FAIL | not form-data");
            return;
        }
        var form = await ctx.Request.ReadFormAsync();
        var file = form.Files["file"];
        if (file == null)
        {
            ctx.Response.StatusCode = 400;
            await ctx.Response.WriteAsync("file field missing");
            AppendLog($"{DateTime.UtcNow:o} | {ip} | upload | {tokenInfo.username} | FAIL | file missing");
            return;
        }

        // Optional: client may send X-Content-Hash header (base64 SHA256)
        string contentHashHeader = ctx.Request.Headers["X-Content-Hash"];
        // Save incoming file to disk
        var saveDir = Path.Combine(AppContext.BaseDirectory, "uploads");
        Directory.CreateDirectory(saveDir);
        var outPath = Path.Combine(saveDir, $"{Guid.NewGuid():N}_{file.FileName}");
        using (var fs = File.Create(outPath))
        {
            await file.CopyToAsync(fs);
        }
        var fileBytes = await File.ReadAllBytesAsync(outPath);
        // verify hash if header present
        if (!string.IsNullOrEmpty(contentHashHeader))
        {
            var expected = Convert.FromBase64String(contentHashHeader);
            using var sha = SHA256.Create();
            var actual = sha.ComputeHash(fileBytes);
            if (!CryptographicEquals(expected, actual))
            {
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsync("Content hash mismatch");
                AppendLog($"{DateTime.UtcNow:o} | {ip} | upload | {tokenInfo.username} | FAIL | content hash mismatch");
                // delete file
                try { File.Delete(outPath); } catch { }
                return;
            }
        }

        ctx.Response.StatusCode = 200;
        await ctx.Response.WriteAsync("File uploaded");
        AppendLog($"{DateTime.UtcNow:o} | {ip} | upload | {tokenInfo.username} | SUCCESS | {fileBytes.Length} bytes -> {outPath}");
    }
    catch (Exception ex)
    {
        ctx.Response.StatusCode = 500;
        await ctx.Response.WriteAsync("Server error");
        AppendLog($"{DateTime.UtcNow:o} | {ip} | upload | - | ERROR | {ex.Message}");
    }
});

// small health endpoint
app.MapGet("/", () => "TLS Server running");

app.Run();

// -------------------- Helpers & types --------------------
static UserRecord CreateUserRecord(string username, string plainPassword)
{
    // PBKDF2 hash
    var salt = RandomNumberGenerator.GetBytes(16);
    using var pbk = new Rfc2898DeriveBytes(plainPassword, salt, 150_000, HashAlgorithmName.SHA256);
    var hash = pbk.GetBytes(32);
    return new UserRecord { Username = username, Salt = Convert.ToBase64String(salt), Hash = Convert.ToBase64String(hash) };
}

static bool VerifyPassword(string password, UserRecord rec)
{
    var salt = Convert.FromBase64String(rec.Salt);
    using var pbk = new Rfc2898DeriveBytes(password, salt, 150_000, HashAlgorithmName.SHA256);
    var hash = pbk.GetBytes(32);
    var expected = Convert.FromBase64String(rec.Hash);
    return CryptographicEquals(hash, expected);
}

static bool CryptographicEquals(byte[] a, byte[] b)
{
    if (a.Length != b.Length) return false;
    int diff = 0;
    for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

record LoginRequest(string Username, string Password);

class UserRecord
{
    public string Username { get; set; } = "";
    public string Salt { get; set; } = "";
    public string Hash { get; set; } = "";
}
