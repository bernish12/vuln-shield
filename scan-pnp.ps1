# VulnShield PnP Scanner v2 — Universal USB Device Detection
# Detects phones connected via ANY cable: data, MTP, or charging-only Type-C/USB
# Outputs JSON array of connected USB/WPD devices

$devices = @()

# ── Scan 1: WPD class (phones in MTP / File Transfer mode — data cable)
try {
    $wpd = Get-PnpDevice -Class 'WPD' -ErrorAction SilentlyContinue | Where-Object {
        $_.InstanceId -notlike 'SWD\*' -and $_.InstanceId -like 'USB\*'
    } | Select-Object FriendlyName, InstanceId, Status
    if ($wpd) { $devices += $wpd }
} catch {}

# ── Scan 2: ALL USB class devices — catches charging-only cable phones
# (phone enumerates as USB Composite Device or USB Power Delivery even on charge cable)
try {
    $usb = Get-PnpDevice -Class 'USB' -ErrorAction SilentlyContinue | Where-Object {
        # Must have a Vendor ID — real hardware
        $_.InstanceId -match 'VID_[0-9A-Fa-f]+' -and
        # Exclude PC-side hubs, host controllers, root hubs
        $_.FriendlyName -notmatch 'Hub|Root Hub|Host Controller|USB Root|Generic USB Hub'
    } | Select-Object FriendlyName, InstanceId, Status
    if ($usb) { $devices += $usb }
} catch {}

# ── Scan 3: AndroidUsbDeviceClass (some phones register here with ADB off)
try {
    $android = Get-PnpDevice -Class 'AndroidUsbDeviceClass' -ErrorAction SilentlyContinue |
        Select-Object FriendlyName, InstanceId, Status
    if ($android) { $devices += $android }
} catch {}

# ── Scan 4: Ports class — some phones appear as COM port devices
try {
    $ports = Get-PnpDevice -Class 'Ports' -ErrorAction SilentlyContinue | Where-Object {
        $_.InstanceId -match 'VID_[0-9A-Fa-f]+' -and
        $_.FriendlyName -notmatch 'Bluetooth'
    } | Select-Object FriendlyName, InstanceId, Status
    if ($ports) { $devices += $ports }
} catch {}

# ── Scan 5: Friendly name keyword search — catches devices with generic class
try {
    $named = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        ($_.FriendlyName -match 'Android|Phone|Mobile|ADB Interface|MTP|RNDIS') -and
        $_.InstanceId -match 'USB\\' -and
        $_.InstanceId -notmatch 'SWD\\'
    } | Select-Object FriendlyName, InstanceId, Status
    if ($named) { $devices += $named }
} catch {}

# Remove duplicates by InstanceId, keep only Status OK or Error (not Unknown/Absent)
$unique = $devices |
    Where-Object { $_.Status -eq 'OK' -or $_.Status -eq 'Error' } |
    Sort-Object InstanceId -Unique

if ($unique.Count -gt 0) {
    $unique | ConvertTo-Json -Compress
} else {
    Write-Output '[]'
}
