using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);
var connection = builder.Configuration.GetConnectionString("VaultCare") ?? "Host=localhost;Database=vaultcare;Username=vaultcare;Password=LocalOnly_ChangeThis_123!";
var jwtKey = Environment.GetEnvironmentVariable("VAULTCARE_JWT_KEY") ?? "local-demo-only-change-this-key-123456789";
if (jwtKey.Length < 32) throw new InvalidOperationException("VAULTCARE_JWT_KEY must be at least 32 characters.");
builder.Services.AddDbContext<VaultDb>(o => o.UseNpgsql(connection));
builder.Services.AddSingleton<SecretCrypto>();
builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
{
    var redis = Environment.GetEnvironmentVariable("REDIS_CONNECTION") ?? "localhost:6379";
    try { return ConnectionMultiplexer.Connect(redis + ",abortConnect=false,connectTimeout=1000"); }
    catch { return ConnectionMultiplexer.Connect("localhost:6379,abortConnect=false,connectTimeout=1000"); }
});
builder.Services.AddCors(o => o.AddPolicy("ui", p => p.WithOrigins("http://localhost:5173", "http://127.0.0.1:5173").AllowAnyHeader().AllowAnyMethod()));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o => o.TokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true, ValidIssuer = "VaultCare", ValidateAudience = true, ValidAudience = "VaultCare.Client",
    ValidateIssuerSigningKey = true, IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
    ValidateLifetime = true, ClockSkew = TimeSpan.FromSeconds(30)
});
builder.Services.AddAuthorization(); builder.Services.AddEndpointsApiExplorer(); builder.Services.AddSwaggerGen();
var app = builder.Build();
app.UseCors("ui"); if (app.Environment.IsDevelopment()) { app.UseSwagger(); app.UseSwaggerUI(); }
app.UseAuthentication(); app.UseAuthorization();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<VaultDb>();
    await db.Database.EnsureCreatedAsync();
    var email = Environment.GetEnvironmentVariable("ADMIN_EMAIL") ?? "admin@vaultcare.local";
    if (!await db.Users.AnyAsync(x => x.Email == email.ToLowerInvariant()))
    {
        db.Users.Add(new User { Email = email.ToLowerInvariant(), DisplayName = "VaultCare Admin", PasswordHash = BCrypt.Net.BCrypt.HashPassword(Environment.GetEnvironmentVariable("ADMIN_PASSWORD") ?? "ChangeMe123!"), Role = "Admin" });
        await db.SaveChangesAsync();
    }
}
app.MapGet("/", () => Results.Ok(new { name = "VaultCare API", version = "1.0.0", docs = "/swagger" }));
app.MapGet("/health", async (VaultDb db) =>
{
    try { return await db.Database.CanConnectAsync() ? Results.Ok(new { status = "Healthy" }) : Results.Json(new { status = "Unhealthy" }, statusCode: 503); }
    catch { return Results.Json(new { status = "Unhealthy" }, statusCode: 503); }
});
app.MapPost("/api/auth/login", async (LoginRequest req, VaultDb db) =>
{
    if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrEmpty(req.Password)) return Results.BadRequest(new { message = "Email and password are required." });
    var user = await db.Users.FirstOrDefaultAsync(x => x.Email == req.Email.Trim().ToLowerInvariant());
    if (user is null || !BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash)) return Results.Unauthorized();
    var claims = new[] { new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()), new Claim(ClaimTypes.Name, user.Email), new Claim(ClaimTypes.Role, user.Role) };
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)); var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken("VaultCare", "VaultCare.Client", claims, expires: DateTime.UtcNow.AddHours(2), signingCredentials: creds);
    await Audit(db, user.Id, "LOGIN", "User", user.Id.ToString(), "Successful login");
    return Results.Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token), user = new { user.Id, user.Email, user.DisplayName, user.Role }, expiresAt = token.ValidTo });
});
app.MapGet("/api/credentials", async (ClaimsPrincipal principal, VaultDb db) =>
{
    var userId = UserId(principal); var admin = principal.IsInRole("Admin");
    var rows = await db.Credentials.Where(x => admin || x.OwnerId == userId).OrderByDescending(x => x.UpdatedAt).Select(x => new CredentialDto(x.Id, x.Title, x.Username, x.Url, x.Category, x.Notes, x.OwnerId, x.CreatedAt, x.UpdatedAt)).ToListAsync();
    return Results.Ok(rows);
}).RequireAuthorization();
app.MapPost("/api/credentials", async (CreateCredentialRequest req, ClaimsPrincipal principal, VaultDb db, SecretCrypto crypto) =>
{
    if (string.IsNullOrWhiteSpace(req.Title)) return Results.ValidationProblem(new Dictionary<string,string[]> { ["title"] = ["Title is required."] });
    if (string.IsNullOrWhiteSpace(req.Secret)) return Results.ValidationProblem(new Dictionary<string,string[]> { ["secret"] = ["Secret is required."] });
    var uid = UserId(principal); var encrypted = crypto.Encrypt(req.Secret);
    var row = new Credential { Title=req.Title.Trim(), Username=req.Username?.Trim() ?? "", Url=req.Url?.Trim() ?? "", Category=string.IsNullOrWhiteSpace(req.Category)?"General":req.Category.Trim(), Notes=req.Notes?.Trim() ?? "", CipherText=encrypted.CipherText, Nonce=encrypted.Nonce, Tag=encrypted.Tag, OwnerId=uid, CreatedAt=DateTimeOffset.UtcNow, UpdatedAt=DateTimeOffset.UtcNow };
    db.Credentials.Add(row); await db.SaveChangesAsync(); await Audit(db, uid, "CREATE", "Credential", row.Id.ToString(), "Credential metadata created");
    return Results.Created($"/api/credentials/{row.Id}", new CredentialDto(row.Id,row.Title,row.Username,row.Url,row.Category,row.Notes,row.OwnerId,row.CreatedAt,row.UpdatedAt));
}).RequireAuthorization();
app.MapGet("/api/credentials/{id:guid}/reveal", async (Guid id, ClaimsPrincipal principal, VaultDb db, SecretCrypto crypto) =>
{
    var uid=UserId(principal); var admin=principal.IsInRole("Admin"); var row=await db.Credentials.FirstOrDefaultAsync(x=>x.Id==id && (admin || x.OwnerId==uid));
    if(row is null) return Results.NotFound();
    try { var secret=crypto.Decrypt(row.CipherText,row.Nonce,row.Tag); await Audit(db,uid,"REVEAL","Credential",row.Id.ToString(),"Secret value revealed"); return Results.Ok(new { secret }); }
    catch(CryptographicException) { return Results.Problem("Unable to decrypt this value. Check the configured encryption key.",statusCode:500); }
}).RequireAuthorization();
app.MapPut("/api/credentials/{id:guid}", async (Guid id, UpdateCredentialRequest req, ClaimsPrincipal principal, VaultDb db, SecretCrypto crypto) =>
{
    var uid=UserId(principal); var admin=principal.IsInRole("Admin"); var row=await db.Credentials.FirstOrDefaultAsync(x=>x.Id==id && (admin || x.OwnerId==uid)); if(row is null)return Results.NotFound();
    if(string.IsNullOrWhiteSpace(req.Title))return Results.BadRequest(new {message="Title is required."});
    row.Title=req.Title.Trim();row.Username=req.Username?.Trim()??"";row.Url=req.Url?.Trim()??"";row.Category=req.Category?.Trim()??"General";row.Notes=req.Notes?.Trim()??"";
    if(!string.IsNullOrEmpty(req.Secret)){var e=crypto.Encrypt(req.Secret);row.CipherText=e.CipherText;row.Nonce=e.Nonce;row.Tag=e.Tag;}
    row.UpdatedAt=DateTimeOffset.UtcNow;await db.SaveChangesAsync();await Audit(db,uid,"UPDATE","Credential",row.Id.ToString(),"Credential updated");
    return Results.Ok(new CredentialDto(row.Id,row.Title,row.Username,row.Url,row.Category,row.Notes,row.OwnerId,row.CreatedAt,row.UpdatedAt));
}).RequireAuthorization();
app.MapDelete("/api/credentials/{id:guid}", async (Guid id, ClaimsPrincipal principal, VaultDb db) =>
{
    var uid=UserId(principal);var row=await db.Credentials.FirstOrDefaultAsync(x=>x.Id==id && (principal.IsInRole("Admin")||x.OwnerId==uid));if(row is null)return Results.NotFound();
    db.Credentials.Remove(row);await db.SaveChangesAsync();await Audit(db,uid,"DELETE","Credential",id.ToString(),"Credential deleted");return Results.NoContent();
}).RequireAuthorization();
app.MapGet("/api/audit", async (int? limit,VaultDb db)=>Results.Ok(await db.AuditEvents.OrderByDescending(x=>x.Timestamp).Take(Math.Clamp(limit??100,1,500)).ToListAsync())).RequireAuthorization(p=>p.RequireRole("Admin"));
app.Run();

static Guid UserId(ClaimsPrincipal p) => Guid.Parse(p.FindFirstValue(ClaimTypes.NameIdentifier) ?? throw new UnauthorizedAccessException());
static async Task Audit(VaultDb db,Guid? userId,string action,string entity,string entityId,string details){db.AuditEvents.Add(new AuditEvent{UserId=userId,Action=action,Entity=entity,EntityId=entityId,Details=details,Timestamp=DateTimeOffset.UtcNow});await db.SaveChangesAsync();}
public sealed record LoginRequest(string Email,string Password);
public sealed record CreateCredentialRequest(string Title,string? Username,string? Url,string Category,string? Notes,string Secret);
public sealed record UpdateCredentialRequest(string Title,string? Username,string? Url,string? Category,string? Notes,string? Secret);
public sealed record CredentialDto(Guid Id,string Title,string Username,string Url,string Category,string Notes,Guid OwnerId,DateTimeOffset CreatedAt,DateTimeOffset UpdatedAt);
public sealed class User { public Guid Id {get;set;}=Guid.NewGuid(); public string Email {get;set;}=""; public string DisplayName {get;set;}=""; public string PasswordHash {get;set;}=""; public string Role {get;set;}="User"; }
public sealed class Credential { public Guid Id {get;set;}=Guid.NewGuid(); public string Title {get;set;}=""; public string Username {get;set;}=""; public string Url {get;set;}=""; public string Category {get;set;}="General"; public string Notes {get;set;}=""; public string CipherText {get;set;}=""; public string Nonce {get;set;}=""; public string Tag {get;set;}=""; public Guid OwnerId {get;set;} public DateTimeOffset CreatedAt {get;set;} public DateTimeOffset UpdatedAt {get;set;} }
public sealed class AuditEvent { public long Id {get;set;} public Guid? UserId {get;set;} public string Action {get;set;}=""; public string Entity {get;set;}=""; public string EntityId {get;set;}=""; public string Details {get;set;}=""; public DateTimeOffset Timestamp {get;set;} }
public sealed class VaultDb(DbContextOptions<VaultDb> options):DbContext(options){public DbSet<User> Users=>Set<User>();public DbSet<Credential> Credentials=>Set<Credential>();public DbSet<AuditEvent> AuditEvents=>Set<AuditEvent>();protected override void OnModelCreating(ModelBuilder b){b.Entity<User>().HasIndex(x=>x.Email).IsUnique();b.Entity<Credential>().HasIndex(x=>new{x.OwnerId,x.Title});b.Entity<AuditEvent>().HasIndex(x=>x.Timestamp);}}
public sealed class SecretCrypto
{
 private readonly byte[] _key;
 public SecretCrypto(){var raw=Environment.GetEnvironmentVariable("VAULTCARE_ENCRYPTION_KEY");if(string.IsNullOrWhiteSpace(raw))throw new InvalidOperationException("Set VAULTCARE_ENCRYPTION_KEY to base64 of 32 random bytes. See README.");try{_key=Convert.FromBase64String(raw);}catch{throw new InvalidOperationException("VAULTCARE_ENCRYPTION_KEY must be valid base64.");}if(_key.Length!=32)throw new InvalidOperationException("VAULTCARE_ENCRYPTION_KEY must decode to exactly 32 bytes.");}
 public (string CipherText,string Nonce,string Tag) Encrypt(string plain){var nonce=RandomNumberGenerator.GetBytes(12);var bytes=Encoding.UTF8.GetBytes(plain);var cipher=new byte[bytes.Length];var tag=new byte[16];using var aes=new AesGcm(_key,16);aes.Encrypt(nonce,bytes,cipher,tag);return(Convert.ToBase64String(cipher),Convert.ToBase64String(nonce),Convert.ToBase64String(tag));}
 public string Decrypt(string cipherText,string nonce,string tag){var c=Convert.FromBase64String(cipherText);var n=Convert.FromBase64String(nonce);var t=Convert.FromBase64String(tag);var plain=new byte[c.Length];using var aes=new AesGcm(_key,16);aes.Decrypt(n,c,t,plain);return Encoding.UTF8.GetString(plain);}
}
