using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

var config = new ConfigurationBuilder()
    .AddUserSecrets<Program>()
    .Build();

var clientId = config["Okta:ClientId"];
var domain = config["Okta:Domain"];
var username = config["Okta:Username"];
var password = config["Okta:Password"];
var redirectUriBase = "http://localhost:8080";
var redirectUriPath = "/login/callback";
var redirectUri = $"{redirectUriBase}{redirectUriPath}";

// Step 1 - Get session token
var client = new HttpClient();
var body = new
{
    username,
    password,
    options = new { multiOptionalFactorEnroll = false, warnBeforePasswordExpired = false }
};

var response = await client.PostAsync($"{domain}/api/v1/authn",
    new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"));

var json = await response.Content.ReadAsStringAsync();
var result = JsonDocument.Parse(json);
var sessionToken = result.RootElement.GetProperty("sessionToken").GetString();

// Step 2 - PKCE parameters
static string Base64UrlEncode(byte[] input)
{
    return Convert.ToBase64String(input)
        .Replace("+", "-")
        .Replace("/", "_")
        .Replace("=", "");
}

static byte[] SHA256Hash(string input)
{
    using var sha256 = SHA256.Create();
    return sha256.ComputeHash(Encoding.ASCII.GetBytes(input));
}

string codeVerifier = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
string codeChallenge = Base64UrlEncode(SHA256Hash(codeVerifier));
string state = Guid.NewGuid().ToString("N");

// Step 3 - Start browser with sessionToken
var authorizeUrl = $"{domain}/oauth2/default/v1/authorize?" + new FormUrlEncodedContent(new Dictionary<string, string>
{
    { "client_id", clientId },
    { "redirect_uri", redirectUri },
    { "response_type", "code" },
    { "scope", "openid profile email" },
    { "code_challenge", codeChallenge },
    { "code_challenge_method", "S256" },
    { "state", state },
    { "sessionToken", sessionToken },
    { "prompt", "none" }
}).ReadAsStringAsync().Result;

Console.WriteLine("Opening browser...");
System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
{
    FileName = authorizeUrl,
    UseShellExecute = true
});

// Step 4: Wait for code on localhost
var builder = WebApplication.CreateBuilder();
var app = builder.Build();

string? authCode = null;

// Match exact path with no trailing slash
app.MapGet(redirectUriPath, async (HttpContext ctx) =>
{
    var code = ctx.Request.Query["code"];
    authCode = code;
    await ctx.Response.WriteAsync("Login complete. You may close this window.");
    Console.WriteLine($"Received code: {code}");
});

_ = app.RunAsync(redirectUriBase);

// Wait until we receive the code
Console.WriteLine($"Listening on {redirectUri} ...");
while (authCode == null)
    await Task.Delay(100);

// Step 5: Exchange code for tokens
var tokenEndpoint = $"{domain}/oauth2/default/v1/token"; // adjust if needed
// var client = new HttpClient();

var tokenRequest = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
{
    Content = new FormUrlEncodedContent(new Dictionary<string, string>
    {
        { "grant_type", "authorization_code" },
        { "code", authCode },
        { "redirect_uri", redirectUri },
        { "client_id", clientId },
        { "code_verifier", codeVerifier } // must match your original
    })
};

tokenRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

var tokenResponse = await client.SendAsync(tokenRequest);
var tokenContent = await tokenResponse.Content.ReadAsStringAsync();

Console.WriteLine("Token response:");
Console.WriteLine(tokenContent);