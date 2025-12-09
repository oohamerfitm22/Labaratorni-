// TlsClient/Program.cs
using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

Console.WriteLine("TLS Client demo");
Console.Write("Server URL (e.g. https://localhost:5001): ");
var serverUrl = Console.ReadLine()?.Trim();
if (string.IsNullOrEmpty(serverUrl)) serverUrl = "https://localhost:5001";

Console.Write("Username: ");
var username = Console.ReadLine() ?? "";
Console.Write("Password: ");
var password = ReadPassword();

using var handler = new HttpClientHandler();

// Для тестового самопідписаного сертифіката — приймаємо його (НЕ для продакшену!)
handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

using var client = new HttpClient(handler) { BaseAddress = new Uri(serverUrl) };

// 1) Login
var loginReq = new { Username = username, Password = password };
var loginResp = await client.PostAsync("/login", new StringContent(JsonSerializer.Serialize(loginReq), Encoding.UTF8, "application/json"));
if (!loginResp.IsSuccessStatusCode)
{
    Console.WriteLine($"Login failed: {loginResp.StatusCode}");
    Console.WriteLine(await loginResp.Content.ReadAsStringAsync());
    return;
}
var loginBody = await loginResp.Content.ReadAsStringAsync();
var loginObj = JsonSerializer.Deserialize<JsonElement>(loginBody);
var token = loginObj.GetProperty("token").GetString();
Console.WriteLine($"Login OK, token: {token}");

// 2) Choose file to send
Console.Write("Path to file to upload: ");
var path = Console.ReadLine();
if (string.IsNullOrEmpty(path) || !File.Exists(path)) { Console.WriteLine("File not found"); return; }
var bytes = await File.ReadAllBytesAsync(path);

// compute SHA256 and base64 it
using var sha = SHA256.Create();
var hash = sha.ComputeHash(bytes);
var hashB64 = Convert.ToBase64String(hash);

// Prepare multipart upload
using var content = new MultipartFormDataContent();
var fileContent = new ByteArrayContent(bytes);
fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
content.Add(fileContent, "file", Path.GetFileName(path));

var req = new HttpRequestMessage(HttpMethod.Post, "/upload");
req.Content = content;
req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
req.Headers.Add("X-Content-Hash", hashB64);

Console.WriteLine("Uploading...");
var uploadResp = await client.SendAsync(req);
Console.WriteLine($"Upload response: {(int)uploadResp.StatusCode} {uploadResp.ReasonPhrase}");
Console.WriteLine(await uploadResp.Content.ReadAsStringAsync());

// helper - read password without echo
static string ReadPassword()
{
    var sb = new StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace && sb.Length > 0) { sb.Length--; continue; }
        sb.Append(key.KeyChar);
    }
    Console.WriteLine();
    return sb.ToString();
}
