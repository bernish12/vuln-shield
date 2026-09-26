# VulnShield PnP Scanner — Outputs JSON of connected mobile devices
# Scans WPD, USB, and AndroidUsbDeviceClass for maximum compatibility

$mobileVIDs = @('04E8','2D95','2A70','22D9','2717','18D1','22B8','12D1','0421','1004','0FCE','0B05','1F3A','2970','2C7C','0E8D','1782','3340','201E','489D','2A45','19D2','1BBB')
$vidPattern = ($mobileVIDs | ForEach-Object { "VID_$_" }) -join '|'

$devices = @()

# Scan WPD class (phones in MTP/File Transfer mode)
try {
    $wpd = Get-PnpDevice -Class 'WPD' -ErrorAction SilentlyContinue | Where-Object {
        $_.InstanceId -notlike 'SWD\*' -and $_.InstanceId -like 'USB\*'
    } | Select-Object FriendlyName, InstanceId, Status
    if ($wpd) { $devices += $wpd }
} catch {}

# Scan USB class for known mobile VIDs
try {
    $usb = Get-PnpDevice -Class 'USB' -ErrorAction SilentlyContinue | Where-Object {
        $_.InstanceId -match $vidPattern -and $_.FriendlyName -notmatch 'Hub|Root|Host|Controller'
    } | Select-Object FriendlyName, InstanceId, Status
    if ($usb) { $devices += $usb }
} catch {}

# Scan AndroidUsbDeviceClass (some phones register here)
try {
    $android = Get-PnpDevice -Class 'AndroidUsbDeviceClass' -ErrorAction SilentlyContinue | Select-Object FriendlyName, InstanceId, Status
    if ($android) { $devices += $android }
} catch {}

# Scan Portable Devices
try {
    $portable = Get-PnpDevice -Class 'WPD' -ErrorAction SilentlyContinue | Where-Object {
        $_.InstanceId -match $vidPattern
    } | Select-Object FriendlyName, InstanceId, Status
    if ($portable) { $devices += $portable }
} catch {}

# Remove duplicates by InstanceId
$unique = $devices | Sort-Object InstanceId -Unique

if ($unique.Count -gt 0) {
    $unique | ConvertTo-Json -Compress
} else {
    Write-Output '[]'
}
