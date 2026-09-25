using System.Collections.Concurrent;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

const string Subnet = "192.168.1";
const string LogRootDirectory = @"L:\Logging";
const string LogFileName = "devices.txt";
const string SettingsFileName = "dashboard-settings.json";

const int PingTimeoutMilliseconds = 1_000;
const int ScanIntervalSeconds = 30;
const int MaximumConcurrentPings = 32;
const int MissesBeforeDown = 4;

var trackedDevices = new Dictionary<int, DeviceStatistics>();
DashboardSnapshot dashboard = new(
    "Waiting for first scan",
    0,
    Array.Empty<DeviceView>());
ScanProgress? currentScan = null;

using var cancellationSource = new CancellationTokenSource();
using var outputLock = new SemaphoreSlim(1, 1);

Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellationSource.Cancel();
};

// The web server runs with the scanner and accepts connections from the LAN.
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://0.0.0.0:5088");

// Weather requests use a separate client so a weather outage cannot stop scans.
using var weatherClient = new HttpClient
{
    Timeout = TimeSpan.FromSeconds(10)
};

// Settings are saved separately from daily device logs.
var settingsStore = new DashboardSettingsStore(Path.Combine(LogRootDirectory, SettingsFileName));
var sessions = new ConcurrentDictionary<string, DateTimeOffset>();
var failedLogins = new ConcurrentDictionary<string, LoginAttempt>();

var app = builder.Build();
app.Use(async (context, next) =>
{
    // Let browsers pick up edits to index.html and always request fresh data.
    context.Response.Headers.CacheControl = "no-store, max-age=0";
    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles();
// All settings changes require a PIN-authenticated session. A JSON request and
// same-origin check also prevent ordinary cross-site forms from changing settings.
bool IsAuthenticated(HttpContext context)
{
    if (!context.Request.Cookies.TryGetValue("dashboard_session", out string? token) ||
        !sessions.TryGetValue(token, out DateTimeOffset expires)) return false;
    if (expires <= DateTimeOffset.UtcNow)
    {
        sessions.TryRemove(token, out _);
        return false;
    }
    return true;
}

bool IsValidSettingsRequest(HttpContext context)
{
    if (!context.Request.HasJsonContentType()) return false;
    string? origin = context.Request.Headers.Origin;
    if (string.IsNullOrEmpty(origin)) return true; // Some local clients omit Origin.
    return Uri.TryCreate(origin, UriKind.Absolute, out Uri? parsed) &&
        string.Equals(parsed.Authority, context.Request.Host.Value, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(parsed.Scheme, context.Request.Scheme, StringComparison.OrdinalIgnoreCase);
}

app.MapGet("/api/settings/theme", () => Results.Ok(new { theme = settingsStore.Theme }));
app.MapGet("/api/settings/clock", () => Results.Ok(settingsStore.Clock));
app.MapGet("/api/settings/session", (HttpContext context) =>
    Results.Ok(new { authenticated = IsAuthenticated(context) }));

app.MapPost("/api/settings/login", (HttpContext context, PinRequest request) =>
{
    if (!IsValidSettingsRequest(context)) return Results.BadRequest();
    string client = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    DateTimeOffset now = DateTimeOffset.UtcNow;
    if (failedLogins.TryGetValue(client, out LoginAttempt? attempt) &&
        attempt.BlockedUntil > now)
        return Results.Json(new { error = "Too many attempts. Try again in five minutes." }, statusCode: 429);

    if (!settingsStore.VerifyPin(request.Pin ?? ""))
    {
        int count = attempt is not null && now - attempt.FirstAttempt < TimeSpan.FromMinutes(5)
            ? attempt.Count + 1 : 1;
        failedLogins[client] = new LoginAttempt(count, count == 1 ? now : attempt!.FirstAttempt,
            count >= 5 ? now.AddMinutes(5) : DateTimeOffset.MinValue);
        return Results.Json(new { error = "Incorrect PIN." }, statusCode: 401);
    }
    failedLogins.TryRemove(client, out _);
    string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    sessions[token] = now.AddHours(2);
    context.Response.Cookies.Append("dashboard_session", token, new CookieOptions
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
        Secure = context.Request.IsHttps,
        Path = "/",
        MaxAge = TimeSpan.FromHours(2)
    });
    return Results.Ok(new { authenticated = true });
});

app.MapPost("/api/settings/logout", (HttpContext context) =>
{
    if (!IsValidSettingsRequest(context)) return Results.BadRequest();
    if (context.Request.Cookies.TryGetValue("dashboard_session", out string? token))
        sessions.TryRemove(token, out _);
    context.Response.Cookies.Delete("dashboard_session", new CookieOptions { Path = "/" });
    return Results.Ok();
});

app.MapPost("/api/settings/theme", (HttpContext context, ThemeRequest request) =>
{
    if (!IsValidSettingsRequest(context)) return Results.BadRequest();
    if (!IsAuthenticated(context)) return Results.Unauthorized();
    if (request.Theme is not ("light" or "dark" or "night"))
        return Results.BadRequest(new { error = "Invalid theme." });
    settingsStore.ChangeTheme(request.Theme);
    return Results.Ok(new { theme = settingsStore.Theme });
});

app.MapPost("/api/settings/clock", (HttpContext context, ClockPreferences request) =>
{
    if (!IsValidSettingsRequest(context)) return Results.BadRequest();
    if (!IsAuthenticated(context)) return Results.Unauthorized();
    if (request.Style is not ("digital12" or "digital24" or "analog" or "flip"))
        return Results.BadRequest(new { error = "Invalid clock style." });
    settingsStore.ChangeClock(request);
    return Results.Ok(settingsStore.Clock);
});

app.MapPost("/api/settings/pin", (HttpContext context, ChangePinRequest request) =>
{
    if (!IsValidSettingsRequest(context)) return Results.BadRequest();
    if (!IsAuthenticated(context)) return Results.Unauthorized();
    if (!settingsStore.VerifyPin(request.CurrentPin ?? ""))
        return Results.Json(new { error = "Current PIN is incorrect." }, statusCode: 400);
    if (request.NewPin is null || request.NewPin.Length < 4 || request.NewPin.Length > 12 ||
        !request.NewPin.All(char.IsAsciiDigit))
        return Results.BadRequest(new { error = "Use 4–12 digits for your new PIN." });
    settingsStore.ChangePin(request.NewPin);
    sessions.Clear(); // Changing the PIN revokes existing sessions.
    context.Response.Cookies.Delete("dashboard_session", new CookieOptions { Path = "/" });
    return Results.Ok(new { message = "PIN changed. Sign in again." });
});

app.MapGet("/api/status", () =>
{
    DashboardSnapshot latest = Volatile.Read(ref dashboard);
    ScanProgress? scan = Volatile.Read(ref currentScan);

    return new
    {
        latest.LastScan,
        latest.Responding,
        latest.Devices,
        IsScanning = scan is not null,
        ScanStarted = scan?.StartedAt,
        ResponsesThisScan = scan?.RespondingHosts.Count ?? 0,
        ServerTimeUnixMilliseconds = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
    };
});

// Keep the external weather service behind this local server. No API key is
// needed for personal use; the browser calls this server on the same host.
app.MapGet("/api/weather/locations", async Task<IResult> (
    string name,
    CancellationToken cancellationToken) =>
{
    name = name.Trim();

    if (name.Length is < 2 or > 80)
    {
        return Results.BadRequest(new { error = "Enter a city or ZIP code." });
    }

    string url = "https://geocoding-api.open-meteo.com/v1/search" +
        $"?name={Uri.EscapeDataString(name)}&count=5&language=en&format=json";

    try
    {
        using HttpResponseMessage response = await weatherClient.GetAsync(
            url, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return Results.StatusCode(StatusCodes.Status502BadGateway);
        }

        return Results.Content(
            await response.Content.ReadAsStringAsync(cancellationToken),
            "application/json");
    }
    catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
    {
        return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
    }
    catch (HttpRequestException)
    {
        return Results.StatusCode(StatusCodes.Status502BadGateway);
    }
});

app.MapGet("/api/weather/current", async Task<IResult> (
    double latitude,
    double longitude,
    CancellationToken cancellationToken) =>
{
    if (!double.IsFinite(latitude) || !double.IsFinite(longitude) ||
        latitude is < -90 or > 90 || longitude is < -180 or > 180)
    {
        return Results.BadRequest(new { error = "Invalid coordinates." });
    }

    string url = "https://api.open-meteo.com/v1/forecast" +
        $"?latitude={latitude.ToString(CultureInfo.InvariantCulture)}" +
        $"&longitude={longitude.ToString(CultureInfo.InvariantCulture)}" +
        "&current=temperature_2m,relative_humidity_2m," +
        "apparent_temperature,precipitation,weather_code," +
        "wind_speed_10m,is_day" +
        "&temperature_unit=fahrenheit&wind_speed_unit=mph" +
        "&precipitation_unit=inch&timezone=auto";

    try
    {
        using HttpResponseMessage response = await weatherClient.GetAsync(
            url, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            return Results.StatusCode(StatusCodes.Status502BadGateway);
        }

        return Results.Content(
            await response.Content.ReadAsStringAsync(cancellationToken),
            "application/json");
    }
    catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
    {
        return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
    }
    catch (HttpRequestException)
    {
        return Results.StatusCode(StatusCodes.Status502BadGateway);
    }
});

await app.StartAsync();

Console.WriteLine($"Scanning {Subnet}.1 through {Subnet}.254");
Console.WriteLine($"Log directory: {LogRootDirectory}");
Console.WriteLine("Dashboard on this PC: http://localhost:5088");
Console.WriteLine("Dashboard on your LAN: http://<this PC's IPv4 address>:5088");
Console.WriteLine($"Devices are marked down after {MissesBeforeDown} missed scans.");
Console.WriteLine("Press Ctrl+C to stop.");

try
{
    while (!cancellationSource.IsCancellationRequested)
    {
        DateTime scanStarted = DateTime.Now;
        var respondingDevices = new ConcurrentDictionary<int, long>();
        Volatile.Write(
            ref currentScan,
            new ScanProgress(
                scanStarted.ToString("yyyy-MM-dd HH:mm:ss"),
                respondingDevices));

        await WriteOutputAsync(
            $"\nScan started: {scanStarted:yyyy-MM-dd HH:mm:ss}",
            cancellationSource.Token);

        await Parallel.ForEachAsync(
            Enumerable.Range(1, 254),
            new ParallelOptions
            {
                MaxDegreeOfParallelism = MaximumConcurrentPings,
                CancellationToken = cancellationSource.Token
            },
            async (hostNumber, cancellationToken) =>
            {
                string address = $"{Subnet}.{hostNumber}";

                try
                {
                    using var ping = new Ping();

                    PingReply reply = await ping.SendPingAsync(
                        address,
                        TimeSpan.FromMilliseconds(PingTimeoutMilliseconds),
                        Array.Empty<byte>(),
                        new PingOptions(),
                        cancellationToken);

                    if (reply.Status == IPStatus.Success)
                    {
                        respondingDevices[hostNumber] = reply.RoundtripTime;

                        await WriteOutputAsync(
                            $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | " +
                            $"{address,-15} | " +
                            $"Responded in {reply.RoundtripTime} ms",
                            cancellationToken);
                    }
                }
                catch (PingException)
                {
                    // No usable ping response from this address.
                }
            });

        DateTime scanFinished = DateTime.Now;

        UpdateDeviceStatistics(respondingDevices.Keys, scanFinished);
        Volatile.Write(
            ref dashboard,
            CreateDashboardSnapshot(scanFinished, respondingDevices.Count));
        Volatile.Write(ref currentScan, null);

        await WriteOutputAsync(
            $"Scan finished: {respondingDevices.Count} device(s) responded.",
            cancellationSource.Token);

        await DisplayDeviceStatisticsAsync(
            scanFinished,
            cancellationSource.Token);

        // Start the next scan 30 seconds after this scan has finished.
        await Task.Delay(
            TimeSpan.FromSeconds(ScanIntervalSeconds),
            cancellationSource.Token);
    }
}
catch (OperationCanceledException) when (cancellationSource.IsCancellationRequested)
{
    Console.WriteLine("\nScanner stopped.");
}
catch (UnauthorizedAccessException exception)
{
    Console.Error.WriteLine(
        $"\nCannot write to {LogRootDirectory}: {exception.Message}");
}
catch (IOException exception)
{
    Console.Error.WriteLine(
        $"\nCannot access the logging directory: {exception.Message}");
}
finally
{
    await app.StopAsync();
}

void UpdateDeviceStatistics(
    IEnumerable<int> respondingHosts,
    DateTime scanFinished)
{
    HashSet<int> responses = respondingHosts.ToHashSet();

    foreach (int hostNumber in responses)
    {
        if (!trackedDevices.ContainsKey(hostNumber))
        {
            trackedDevices[hostNumber] = new DeviceStatistics
            {
                HostNumber = hostNumber,
                FirstSeen = scanFinished,
                LastSeen = scanFinished,
                CurrentUpSince = scanFinished
            };
        }
    }

    foreach (DeviceStatistics device in trackedDevices.Values)
    {
        if (responses.Contains(device.HostNumber))
        {
            device.LastSeen = scanFinished;

            if (device.IsDown)
            {
                device.IsDown = false;
                device.CurrentUpSince = scanFinished;
                device.CurrentDownSince = null;
            }

            device.ConsecutiveMisses = 0;
            device.FirstMissAt = null;
            device.UpChecks++;
            continue;
        }

        device.ConsecutiveMisses++;

        if (device.IsDown)
        {
            device.DownChecks++;
            continue;
        }

        if (device.ConsecutiveMisses == 1)
        {
            device.FirstMissAt = scanFinished;
        }

        // Until the fourth miss, treat the device as up.
        device.UpChecks++;

        if (device.ConsecutiveMisses == MissesBeforeDown)
        {
            device.IsDown = true;

            // Reclassify the four uncertain scans as downtime.
            device.UpChecks -= MissesBeforeDown;
            device.DownChecks += MissesBeforeDown;

            device.CurrentDownSince = device.FirstMissAt ?? scanFinished;
            device.LastCompletedUptime =
                device.CurrentDownSince.Value - device.CurrentUpSince;
        }
    }
}

DashboardSnapshot CreateDashboardSnapshot(
    DateTime scanFinished,
    int respondingCount)
{
    DeviceView[] devices = trackedDevices.Values
        .OrderBy(device => device.HostNumber)
        .Select(device =>
        {
            long totalChecks = device.UpChecks + device.DownChecks;

            double upPercent = totalChecks == 0
                ? 0
                : 100.0 * device.UpChecks / totalChecks;

            string status = device.IsDown
                ? "DOWN"
                : device.ConsecutiveMisses == 0
                    ? "UP"
                    : $"UP ({device.ConsecutiveMisses}/{MissesBeforeDown} missed)";

            string uptime = device.IsDown
                ? FormatDuration(device.LastCompletedUptime)
                : FormatDuration(scanFinished - device.CurrentUpSince);

            string downtime = device.IsDown
                ? FormatDuration(
                    scanFinished - (device.CurrentDownSince ?? scanFinished))
                : "—";

            return new DeviceView(
                $"{Subnet}.{device.HostNumber}",
                status,
                uptime,
                downtime,
                Math.Round(upPercent, 2),
                Math.Round(100 - upPercent, 2),
                device.ConsecutiveMisses,
                device.LastSeen.ToString("yyyy-MM-dd HH:mm:ss"),
                device.IsDown
                    ? null
                    : new DateTimeOffset(device.CurrentUpSince)
                        .ToUnixTimeMilliseconds(),
                device.IsDown
                    ? new DateTimeOffset(device.CurrentDownSince ?? scanFinished)
                        .ToUnixTimeMilliseconds()
                    : null);
        })
        .ToArray();

    return new DashboardSnapshot(
        scanFinished.ToString("yyyy-MM-dd HH:mm:ss"),
        respondingCount,
        devices);
}

async Task DisplayDeviceStatisticsAsync(
    DateTime currentTime,
    CancellationToken cancellationToken)
{
    await WriteOutputAsync(
        "\nTracked device statistics:",
        cancellationToken);

    if (trackedDevices.Count == 0)
    {
        await WriteOutputAsync(
            "No devices have responded yet.",
            cancellationToken);
        return;
    }

    foreach (DeviceStatistics device in
             trackedDevices.Values.OrderBy(device => device.HostNumber))
    {
        string address = $"{Subnet}.{device.HostNumber}";
        long totalChecks = device.UpChecks + device.DownChecks;

        double upPercent = totalChecks == 0
            ? 0
            : 100.0 * device.UpChecks / totalChecks;

        double downPercent = 100 - upPercent;

        if (!device.IsDown)
        {
            string status = device.ConsecutiveMisses == 0
                ? "UP"
                : $"UP ({device.ConsecutiveMisses}/{MissesBeforeDown} missed)";

            await WriteOutputAsync(
                $"{address,-15} | {status,-16} | " +
                $"Estimated uptime: " +
                $"{FormatDuration(currentTime - device.CurrentUpSince),-18} | " +
                $"Up: {upPercent,6:F2}% | Down: {downPercent,6:F2}%",
                cancellationToken);
        }
        else
        {
            TimeSpan downtime =
                currentTime - (device.CurrentDownSince ?? currentTime);

            await WriteOutputAsync(
                $"{address,-15} | {"DOWN",-16} | " +
                $"Downtime: {FormatDuration(downtime),-18} | " +
                $"Last uptime: " +
                $"{FormatDuration(device.LastCompletedUptime),-18} | " +
                $"Up: {upPercent,6:F2}% | Down: {downPercent,6:F2}% | " +
                $"Misses: {device.ConsecutiveMisses}",
                cancellationToken);
        }
    }
}

async Task WriteOutputAsync(
    string message,
    CancellationToken cancellationToken)
{
    // Multiple pings can finish simultaneously. Serialize file/console output.
    await outputLock.WaitAsync(cancellationToken);

    try
    {
        DateTime now = DateTime.Now;

        string dailyDirectory = Path.Combine(
            LogRootDirectory,
            now.ToString("yyyy"),
            now.ToString("MM"),
            now.ToString("dd"));

        string logFilePath = Path.Combine(dailyDirectory, LogFileName);

        Console.WriteLine(message);
        Directory.CreateDirectory(dailyDirectory);

        // Creates the file if absent, and appends if it already exists.
        await File.AppendAllTextAsync(
            logFilePath,
            message + Environment.NewLine,
            cancellationToken);
    }
    finally
    {
        outputLock.Release();
    }
}

static string FormatDuration(TimeSpan duration)
{
    if (duration < TimeSpan.Zero)
    {
        duration = TimeSpan.Zero;
    }

    if (duration.TotalDays >= 1)
    {
        return
            $"{(int)duration.TotalDays}d " +
            $"{duration.Hours:00}h " +
            $"{duration.Minutes:00}m " +
            $"{duration.Seconds:00}s";
    }

    return
        $"{(int)duration.TotalHours:00}h " +
        $"{duration.Minutes:00}m " +
        $"{duration.Seconds:00}s";
}

sealed class DeviceStatistics
{
    public int HostNumber { get; init; }
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; set; }
    public DateTime CurrentUpSince { get; set; }
    public DateTime? FirstMissAt { get; set; }
    public DateTime? CurrentDownSince { get; set; }
    public TimeSpan LastCompletedUptime { get; set; }
    public int ConsecutiveMisses { get; set; }
    public long UpChecks { get; set; }
    public long DownChecks { get; set; }
    public bool IsDown { get; set; }
}

record DashboardSnapshot(
    string LastScan,
    int Responding,
    DeviceView[] Devices);

record ScanProgress(
    string StartedAt,
    ConcurrentDictionary<int, long> RespondingHosts);

record DeviceView(
    string Address,
    string Status,
    string Uptime,
    string Downtime,
    double UpPercent,
    double DownPercent,
    int Misses,
    string LastSeen,
    long? UpSinceUnixMilliseconds,
    long? DownSinceUnixMilliseconds);

record PinRequest(string? Pin);
record ChangePinRequest(string? CurrentPin, string? NewPin);
record ThemeRequest(string? Theme);
record ClockPreferences(string Style, bool ShowSeconds, bool ShowDate);
record LoginAttempt(int Count, DateTimeOffset FirstAttempt, DateTimeOffset BlockedUntil);

sealed class DashboardSettingsStore
{
    private readonly string path;
    private readonly object gate = new();
    private StoredSettings settings;

    public DashboardSettingsStore(string path)
    {
        this.path = path;
        if (File.Exists(path))
        {
            settings = JsonSerializer.Deserialize<StoredSettings>(File.ReadAllText(path))
                ?? throw new InvalidDataException("Invalid dashboard settings file.");
            if (settings.Salt.Length < 16 || settings.Hash.Length < 32 ||
                settings.Theme is not ("light" or "dark" or "night"))
                throw new InvalidDataException("Invalid dashboard settings values.");
            // Previously saved files omit clock preferences; keep their PIN and theme.
            if (settings.ClockStyle is not ("digital12" or "digital24" or "analog" or "flip"))
                settings = settings with { ClockStyle = "digital12" };
            settings = settings with
            {
                ClockShowSeconds = settings.ClockShowSeconds ?? true,
                ClockShowDate = settings.ClockShowDate ?? true
            };
        }
        else
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            settings = new StoredSettings("light", salt, HashPin("1234", salt),
                "digital12", true, true);
            Save();
        }
    }

    public string Theme { get { lock (gate) return settings.Theme; } }
    public ClockPreferences Clock
    {
        get
        {
            lock (gate) return new ClockPreferences(settings.ClockStyle!,
            settings.ClockShowSeconds ?? true, settings.ClockShowDate ?? true);
        }
    }

    public bool VerifyPin(string pin)
    {
        lock (gate)
        {
            byte[] candidate = HashPin(pin, settings.Salt);
            return CryptographicOperations.FixedTimeEquals(candidate, settings.Hash);
        }
    }

    public void ChangeTheme(string theme)
    {
        lock (gate)
        {
            settings = settings with { Theme = theme };
            Save();
        }
    }

    public void ChangeClock(ClockPreferences requested)
    {
        lock (gate)
        {
            settings = settings with
            {
                ClockStyle = requested.Style,
                ClockShowSeconds = requested.ShowSeconds,
                ClockShowDate = requested.ShowDate
            };
            Save();
        }
    }

    public void ChangePin(string pin)
    {
        lock (gate)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            settings = settings with { Salt = salt, Hash = HashPin(pin, salt) };
            Save();
        }
    }

    private static byte[] HashPin(string pin, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(pin, salt, 210_000, HashAlgorithmName.SHA256, 32);

    private void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(settings));
        File.Move(temporary, path, true);
    }

    private sealed record StoredSettings(string Theme, byte[] Salt, byte[] Hash,
        string? ClockStyle = null, bool? ClockShowSeconds = null, bool? ClockShowDate = null);
}
