using System.Collections.Concurrent;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Logging;

const string Subnet = "192.168.1";
const string LogRootDirectory = @"L:\Logging";
const string LogFileName = "devices.txt";
const string WeatherLogFileName = "weather.txt";
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
using var weatherWakeup = new SemaphoreSlim(0, 1);
var weatherJsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
WeatherSnapshot? latestWeather = null;
string? latestWeatherError = null;

Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellationSource.Cancel();
};

// The web server runs with the scanner and accepts connections from the LAN.
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://0.0.0.0:5088");
// No scanner or framework informational messages in the console.
// Fatal file-system errors below still go to stderr so a logging failure is visible.
builder.Logging.ClearProviders();

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
// Explicitly serve bundled Ogg Vorbis soundscapes with the audio MIME type.
// This is configured at startup, before any requests are handled.
var staticContentTypes = new FileExtensionContentTypeProvider();
staticContentTypes.Mappings[".ogg"] = "audio/ogg";
app.UseStaticFiles(new StaticFileOptions { ContentTypeProvider = staticContentTypes });
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
app.MapGet("/api/settings/sleep", () => Results.Ok(settingsStore.Sleep));
app.MapGet("/api/settings/clock", () => Results.Ok(settingsStore.Clock));
app.MapGet("/api/settings/weather", () => Results.Ok(new { zipCode = settingsStore.WeatherZip }));
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
    if (!settingsStore.TryChangeTheme(request.Theme))
        return Results.Json(new { error = "Theme changes are disabled while the sleep schedule is active." },
            statusCode: StatusCodes.Status409Conflict);
    return Results.Ok(new { theme = settingsStore.Theme });
});

app.MapPost("/api/settings/sleep", (HttpContext context, SleepScheduleRequest request) =>
{
    if (!IsValidSettingsRequest(context)) return Results.BadRequest();
    if (!IsAuthenticated(context)) return Results.Unauthorized();
    if (!DashboardSettingsStore.IsValidTime(request.StartTime) ||
        !DashboardSettingsStore.IsValidTime(request.StopTime) ||
        request.StartTime == request.StopTime)
        return Results.BadRequest(new { error = "Choose valid, different start and stop times." });
    settingsStore.ChangeSleep(request.Enabled, request.StartTime!, request.StopTime!);
    return Results.Ok(settingsStore.Sleep);
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

app.MapPost("/api/settings/weather", (HttpContext context, WeatherZipRequest request) =>
{
    if (!IsValidSettingsRequest(context)) return Results.BadRequest();
    if (!IsAuthenticated(context)) return Results.Unauthorized();
    string zip = request.ZipCode?.Trim() ?? "";
    if (!DashboardSettingsStore.IsValidWeatherZip(zip))
        return Results.BadRequest(new { error = "Enter a US ZIP code (12345 or 12345-6789)." });

    if (settingsStore.ChangeWeatherZip(zip))
    {
        // Invalidate stale coordinates/observations when the location changes.
        Volatile.Write(ref latestWeather, null);
        Volatile.Write(ref latestWeatherError, null);
        try { weatherWakeup.Release(); }
        catch (SemaphoreFullException) { /* An immediate refresh is already queued. */ }
    }
    return Results.Ok(new { zipCode = settingsStore.WeatherZip });
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

// Weather is fetched and logged by the server every five minutes, independent
// of whether a browser has the dashboard open. The browser only reads its cache.
app.MapGet("/api/weather/current", () =>
{
    WeatherSnapshot? current = Volatile.Read(ref latestWeather);
    if (current is not null && current.ZipCode == settingsStore.WeatherZip)
        return Results.Content(current.Payload, "application/json");

    return Results.Json(new
    {
        error = Volatile.Read(ref latestWeatherError) ??
            "Waiting for the first weather reading. Retrying automatically."
    }, statusCode: StatusCodes.Status503ServiceUnavailable);
});

// One background worker owns external requests, preventing browser refreshes
// from duplicating rows in the daily weather log.
async Task RunWeatherLoopAsync(CancellationToken cancellationToken)
{
    ZipCoordinates? cachedCoordinates = null;
    while (!cancellationToken.IsCancellationRequested)
    {
        // Consume a ZIP-change signal that triggered the current refresh.
        // This prevents a second immediate request for the same new location.
        while (weatherWakeup.Wait(0)) { }
        string zipCode = settingsStore.WeatherZip;
        try
        {
            string fiveDigitZip = zipCode[..5]; // ZIP+4 uses the 5-digit area.
            if (cachedCoordinates is null || cachedCoordinates.ZipCode != fiveDigitZip)
                cachedCoordinates = await ResolveZipAsync(fiveDigitZip, cancellationToken);

            ZipCoordinates location = cachedCoordinates;
            string url = "https://api.open-meteo.com/v1/forecast" +
                $"?latitude={location.Latitude.ToString(CultureInfo.InvariantCulture)}" +
                $"&longitude={location.Longitude.ToString(CultureInfo.InvariantCulture)}" +
                "&current=temperature_2m,relative_humidity_2m," +
                "apparent_temperature,precipitation,rain,showers,snowfall," +
                "weather_code,cloud_cover,pressure_msl,surface_pressure," +
                "wind_speed_10m,wind_direction_10m,wind_gusts_10m,is_day" +
                "&temperature_unit=fahrenheit&wind_speed_unit=mph" +
                "&precipitation_unit=inch&timezone=auto";

            using HttpResponseMessage response = await weatherClient.GetAsync(url, cancellationToken);
            response.EnsureSuccessStatusCode();
            using JsonDocument data = JsonDocument.Parse(
                await response.Content.ReadAsStringAsync(cancellationToken));
            JsonElement source = data.RootElement;
            JsonElement current = source.GetProperty("current");
            JsonElement units = source.GetProperty("current_units");
            if (current.ValueKind != JsonValueKind.Object ||
                !current.TryGetProperty("temperature_2m", out JsonElement temperature) ||
                temperature.ValueKind != JsonValueKind.Number)
                throw new InvalidDataException("Weather response is missing current readings.");

            // A ZIP may have been changed while the request was in flight.
            if (settingsStore.WeatherZip != zipCode) continue;
            DateTimeOffset recordedAt = DateTimeOffset.Now;
            string abbreviation = source.TryGetProperty("timezone_abbreviation", out var timezone)
                ? timezone.GetString() ?? "" : "";
            string payload = JsonSerializer.Serialize(new
            {
                zipCode,
                location = location.Name,
                checkedAt = recordedAt,
                timezone_abbreviation = abbreviation,
                current = current.Clone(),
                current_units = units.Clone()
            }, weatherJsonOptions);

            // Each weather.txt line contains all fields *and their units* returned
            // by Open-Meteo, plus the ZIP, place and the local recording timestamp.
            string logLine = JsonSerializer.Serialize(new
            {
                loggedAt = recordedAt,
                zipCode,
                location = location.Name,
                source = "Open-Meteo",
                weather = source.Clone()
            }, weatherJsonOptions);
            await WriteWeatherLogAsync(logLine, cancellationToken);
            Volatile.Write(ref latestWeather, new WeatherSnapshot(zipCode, payload));
            Volatile.Write(ref latestWeatherError, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            break;
        }
        catch (Exception exception) when (exception is HttpRequestException or
            JsonException or OperationCanceledException or IOException or
            UnauthorizedAccessException or InvalidOperationException)
        {
            if (settingsStore.WeatherZip == zipCode)
            {
                Volatile.Write(ref latestWeatherError,
                    exception is InvalidDataException ? exception.Message :
                    "Weather update failed; the server will retry automatically.");
                // Errors are logged separately from readings, never as fake weather data.
                try
                {
                    await WriteWeatherLogAsync(JsonSerializer.Serialize(new
                    {
                        loggedAt = DateTimeOffset.Now,
                        zipCode,
                        error = exception.Message
                    }, weatherJsonOptions), cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (IOException fileError)
                {
                    Console.Error.WriteLine($"Cannot write weather log: {fileError.Message}");
                }
                catch (UnauthorizedAccessException fileError)
                {
                    Console.Error.WriteLine($"Cannot write weather log: {fileError.Message}");
                }
            }
        }

        try { await weatherWakeup.WaitAsync(TimeSpan.FromMinutes(5), cancellationToken); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
    }
}

async Task<ZipCoordinates> ResolveZipAsync(string zip, CancellationToken cancellationToken)
{
    // Zippopotam.us provides coordinates for US ZIP codes without an API key.
    using HttpResponseMessage response = await weatherClient.GetAsync(
        "https://api.zippopotam.us/us/" + zip, cancellationToken);
    if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        throw new InvalidDataException("The weather ZIP code could not be located.");
    response.EnsureSuccessStatusCode();
    using JsonDocument document = JsonDocument.Parse(
        await response.Content.ReadAsStringAsync(cancellationToken));
    JsonElement root = document.RootElement;
    if (!root.TryGetProperty("places", out JsonElement places) ||
        places.ValueKind != JsonValueKind.Array || places.GetArrayLength() == 0)
        throw new InvalidDataException("No location was returned for this ZIP code.");
    JsonElement place = places[0];
    if (!double.TryParse(place.GetProperty("latitude").GetString(),
            NumberStyles.Float, CultureInfo.InvariantCulture, out double latitude) ||
        !double.TryParse(place.GetProperty("longitude").GetString(),
            NumberStyles.Float, CultureInfo.InvariantCulture, out double longitude))
        throw new InvalidDataException("Weather location has invalid coordinates.");
    string city = place.GetProperty("place name").GetString() ?? zip;
    string state = place.GetProperty("state abbreviation").GetString() ?? "";
    return new ZipCoordinates(zip, latitude, longitude,
        string.IsNullOrEmpty(state) ? city : $"{city}, {state}");
}

async Task WriteWeatherLogAsync(string line, CancellationToken cancellationToken)
{
    await outputLock.WaitAsync(cancellationToken);
    try
    {
        DateTime now = DateTime.Now;
        string directory = Path.Combine(LogRootDirectory, now.ToString("yyyy"),
            now.ToString("MM"), now.ToString("dd"));
        Directory.CreateDirectory(directory);
        await File.AppendAllTextAsync(Path.Combine(directory, WeatherLogFileName),
            line + Environment.NewLine, cancellationToken);
    }
    finally { outputLock.Release(); }
}

await app.StartAsync();
Task weatherWorker = RunWeatherLoopAsync(cancellationSource.Token);

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
    // Normal shutdown. Device and weather logs were already written to disk.
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
    cancellationSource.Cancel();
    await weatherWorker;
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
    // Multiple pings can finish simultaneously; serialize disk writes.
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
record WeatherZipRequest(string? ZipCode);
record WeatherSnapshot(string ZipCode, string Payload);
record ZipCoordinates(string ZipCode, double Latitude, double Longitude, string Name);
record SleepScheduleRequest(bool Enabled, string? StartTime, string? StopTime);
record SleepSchedulePreferences(bool Enabled, string StartTime, string StopTime, int ServerUtcOffsetMinutes);
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
            // Previously saved files omit some preferences; keep their PIN and theme.
            bool needsWeatherZipMigration = !IsValidWeatherZip(settings.WeatherZip);
            if (settings.ClockStyle is not ("digital12" or "digital24" or "analog" or "flip"))
                settings = settings with { ClockStyle = "digital12" };
            settings = settings with
            {
                ClockShowSeconds = settings.ClockShowSeconds ?? true,
                ClockShowDate = settings.ClockShowDate ?? true,
                SleepEnabled = settings.SleepEnabled ?? false,
                SleepStartTime = IsValidTime(settings.SleepStartTime) &&
                    settings.SleepStartTime != settings.SleepStopTime ? settings.SleepStartTime : "22:00",
                SleepStopTime = IsValidTime(settings.SleepStopTime) &&
                    settings.SleepStartTime != settings.SleepStopTime ? settings.SleepStopTime : "07:00",
                WeatherZip = IsValidWeatherZip(settings.WeatherZip) ? settings.WeatherZip : "37615-5029"
            };
            if (needsWeatherZipMigration) Save();
        }
        else
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            settings = new StoredSettings("light", salt, HashPin("1234", salt),
                "digital12", true, true, WeatherZip: "37615-5029");
            Save();
        }
    }

    public string Theme { get { lock (gate) return settings.Theme; } }
    public string WeatherZip { get { lock (gate) return settings.WeatherZip ?? "37615-5029"; } }

    public static bool IsValidWeatherZip(string? zip) =>
        zip is not null && (System.Text.RegularExpressions.Regex.IsMatch(zip,
            @"^[0-9]{5}(-[0-9]{4})?$"));

    public bool ChangeWeatherZip(string zip)
    {
        lock (gate)
        {
            if (settings.WeatherZip == zip) return false;
            settings = settings with { WeatherZip = zip };
            Save();
            return true;
        }
    }
    public SleepSchedulePreferences Sleep
    {
        get
        {
            lock (gate) return new SleepSchedulePreferences(
            settings.SleepEnabled ?? false,
            settings.SleepStartTime ?? "22:00",
            settings.SleepStopTime ?? "07:00",
            (int)DateTimeOffset.Now.Offset.TotalMinutes);
        }
    }
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

    // Recheck at save time, not just when the page was opened.
    public bool TryChangeTheme(string theme)
    {
        lock (gate)
        {
            if (IsInSleepWindow(settings.SleepEnabled ?? false,
                settings.SleepStartTime ?? "22:00", settings.SleepStopTime ?? "07:00",
                TimeOnly.FromDateTime(DateTime.Now))) return false;
            settings = settings with { Theme = theme };
            Save();
            return true;
        }
    }

    public void ChangeSleep(bool enabled, string startTime, string stopTime)
    {
        lock (gate)
        {
            settings = settings with
            {
                SleepEnabled = enabled,
                SleepStartTime = startTime,
                SleepStopTime = stopTime
            };
            Save();
        }
    }

    public static bool IsValidTime(string? value) =>
        TimeOnly.TryParseExact(value, "HH:mm", CultureInfo.InvariantCulture,
            DateTimeStyles.None, out _);

    private static bool IsInSleepWindow(bool enabled, string start, string stop, TimeOnly now)
    {
        if (!enabled || !IsValidTime(start) || !IsValidTime(stop) || start == stop)
            return false;
        var startAt = TimeOnly.ParseExact(start, "HH:mm", CultureInfo.InvariantCulture);
        var stopAt = TimeOnly.ParseExact(stop, "HH:mm", CultureInfo.InvariantCulture);
        return startAt < stopAt ? now >= startAt && now < stopAt
            : now >= startAt || now < stopAt;
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
        string? ClockStyle = null, bool? ClockShowSeconds = null, bool? ClockShowDate = null,
        bool? SleepEnabled = null, string? SleepStartTime = null, string? SleepStopTime = null,
        string? WeatherZip = null);
}
