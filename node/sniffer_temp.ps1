$ErrorActionPreference = 'SilentlyContinue'
$LocalIP    = '192.168.1.12'
$LocalPort  = 27281
$RemoteIP   = '166.117.54.146'
$RemotePort = 30000
$ProtoNum   = 6
$IsUdp      = $false

if (-not $LocalIP) {
  $probe = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
  $probe.Connect($RemoteIP, 9)
  $LocalIP = $probe.LocalEndPoint.Address.ToString()
  $probe.Close()
}

$localBytes  = [Net.IPAddress]::Parse($LocalIP).GetAddressBytes()
$remoteBytes = [Net.IPAddress]::Parse($RemoteIP).GetAddressBytes()
$buffer      = New-Object byte[] 65536

function Test-IpMatch([byte[]]$buf, [int]$offset, [byte[]]$ip) {
  return ($buf[$offset] -eq $ip[0] -and $buf[$offset+1] -eq $ip[1] -and $buf[$offset+2] -eq $ip[2] -and $buf[$offset+3] -eq $ip[3])
}

function Format-Packet([byte[]]$buf, [int]$length, [int]$baseOffset) {
  if ($baseOffset -ge $length -or (($buf[$baseOffset] -band 0xF0) -ne 0x40) -or $buf[$baseOffset+9] -ne $ProtoNum) { return $null }

  $ipHeaderLen = ($buf[$baseOffset] -band 0x0F) * 4
  $transportOffset = $baseOffset + $ipHeaderLen
  $srcPort = $buf[$transportOffset] * 256 + $buf[$transportOffset+1]
  $dstPort = $buf[$transportOffset+2] * 256 + $buf[$transportOffset+3]

  if ($IsUdp) {
    $dataOffset = $transportOffset + 8
  } else {
    $tcpHeaderLen = (($buf[$transportOffset+12] -band 0xF0) -shr 4) * 4
    $dataOffset = $transportOffset + $tcpHeaderLen
  }

  if ($dataOffset -ge $length) { return $null }

  if ($AnyRemote) {
    # Modo UDP comodín (*:0): basta con que el puerto de origen o destino sea el puerto del juego
    if ($srcPort -eq $LocalPort) { $direction = 'Send' }
    elseif ($dstPort -eq $LocalPort) { $direction = 'Recv' }
    else { return $null }
  } else {
    $isSend = (Test-IpMatch $buf ($baseOffset+12) $localBytes) -and (!$LocalPort -or $srcPort -eq $LocalPort) -and (Test-IpMatch $buf ($baseOffset+16) $remoteBytes) -and ($dstPort -eq $RemotePort)
    $isRecv = (Test-IpMatch $buf ($baseOffset+12) $remoteBytes) -and ($srcPort -eq $RemotePort) -and (Test-IpMatch $buf ($baseOffset+16) $localBytes) -and (!$LocalPort -or $dstPort -eq $LocalPort)

    if ($isSend) { $direction = 'Send' }
    elseif ($isRecv) { $direction = 'Recv' }
    else { return $null }
  }

  $payloadLen = $length - $dataOffset
  $payload = New-Object byte[] $payloadLen
  [Array]::Copy($buf, $dataOffset, $payload, 0, $payloadLen)

  $time = Get-Date -Format 'HH:mm:ss'
  $base64 = [Convert]::ToBase64String($payload)
  return "[$time]`t[$direction]`t$base64"
}

# Intentar inicializar Npcap (wpcap.dll)
$capHandle = [IntPtr]::Zero
try {
  Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct bpf_program_t { public uint bf_len; public IntPtr bf_insns; }

public static class Npcap {
  [DllImport("wpcap.dll", CharSet=CharSet.Ansi)] public static extern int pcap_findalldevs(ref IntPtr alldevs, StringBuilder errbuf);
  [DllImport("wpcap.dll")] public static extern void pcap_freealldevs(IntPtr alldevs);
  [DllImport("wpcap.dll", CharSet=CharSet.Ansi)] public static extern IntPtr pcap_open_live(string dev, int snaplen, int promisc, int to_ms, StringBuilder errbuf);
  [DllImport("wpcap.dll")] public static extern int pcap_next_ex(IntPtr p, ref IntPtr hdr, ref IntPtr data);
  [DllImport("wpcap.dll")] public static extern int pcap_datalink(IntPtr p);
  [DllImport("wpcap.dll", CharSet=CharSet.Ansi)] public static extern int pcap_compile(IntPtr p, ref bpf_program_t fp, string str, int optimize, uint netmask);
  [DllImport("wpcap.dll")] public static extern int pcap_setfilter(IntPtr p, ref bpf_program_t fp);
}
'@

  Get-Service npcap, npf | Where-Object Status -ne 'Running' | Start-Service
  $wmiConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Where-Object { $_.IPAddress -contains $LocalIP } | Select-Object -First 1
  $adapterAlias = if ($wmiConfig) { (Get-WmiObject Win32_NetworkAdapter -Filter "Index=$($wmiConfig.Index)").NetConnectionID }

  $devListPtr = [IntPtr]::Zero
  $errBuf = New-Object Text.StringBuilder 256

  if ([Npcap]::pcap_findalldevs([ref]$devListPtr, $errBuf) -eq 0 -and $devListPtr -ne [IntPtr]::Zero) {
    $currentPtr = $devListPtr
    $firstDev = $null
    $selectedDev = $null

    while ($currentPtr -ne [IntPtr]::Zero) {
      $namePtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($currentPtr, 8)
      $descPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($currentPtr, 16)
      $name = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($namePtr)
      $desc = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($descPtr)

      if (-not $name) { break }
      if (-not $firstDev) { $firstDev = $name }

      $isLoopback = $LocalIP.StartsWith('127.') -and ($desc -match 'loopback')
      $isMatchingAdapter = $adapterAlias -and ($desc -match [regex]::Escape($adapterAlias))

      if ($isLoopback -or $isMatchingAdapter) {
        $selectedDev = $name
        break
      }
      $currentPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($currentPtr, 0)
    }

    [Npcap]::pcap_freealldevs($devListPtr)
    if (-not $selectedDev) { $selectedDev = $firstDev }

    if ($selectedDev) {
      $capHandle = [Npcap]::pcap_open_live($selectedDev, 65535, 1, 500, $errBuf)
      if ($capHandle -ne [IntPtr]::Zero) {
        $filterProg = New-Object bpf_program_t
        $protoName = if ($IsUdp) { 'udp' } else { 'tcp' }
        $filterStr = "$protoName and host $RemoteIP and port $RemotePort"

        if ([Npcap]::pcap_compile($capHandle, [ref]$filterProg, $filterStr, 1, 0xffffffff) -ge 0) {
          $null = [Npcap]::pcap_setfilter($capHandle, [ref]$filterProg)
        }
        $dataLink = [Npcap]::pcap_datalink($capHandle)
        Write-Output "[INFO] Capturando con Npcap ($selectedDev)..."
      }
    }
  }
} catch {}

# Fallback a Raw Socket si Npcap no pudo iniciarse
if ($capHandle -eq [IntPtr]::Zero) {
  try {
    $rawSocket = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Raw, [Net.Sockets.ProtocolType]::IP)
    $rawSocket.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Parse($LocalIP), 0)))
    $null = $rawSocket.IOControl([Net.Sockets.IOControlCode]::ReceiveAll, [BitConverter]::GetBytes([int]1), $null)
    $rawSocket.ReceiveTimeout = 1000
    Write-Output '[INFO] Capturando con raw socket (solo paquetes Send)...'
  } catch {
    Write-Output '[ERR] No se pudo iniciar Npcap ni raw socket.'
    exit 1
  }
}

# Bucle principal de lectura
$hdrPtr = [IntPtr]::Zero
$dataPtr = [IntPtr]::Zero

while ($true) {
  if ($capHandle -ne [IntPtr]::Zero) {
    if ([Npcap]::pcap_next_ex($capHandle, [ref]$hdrPtr, [ref]$dataPtr) -le 0) { continue }
    $packetLen = [Runtime.InteropServices.Marshal]::ReadInt32($hdrPtr, 8)
    if ($packetLen -le 0) { continue }

    [Runtime.InteropServices.Marshal]::Copy($dataPtr, $buffer, 0, $packetLen)
    $etherType = $buffer[12] * 256 + $buffer[13]
    $baseOffset = if ($dataLink -eq 0) { 4 } elseif ($etherType -eq 0x8100) { 18 } else { 14 }
  } else {
    try { $packetLen = $rawSocket.Receive($buffer) } catch { $packetLen = 0 }
    if ($packetLen -lt 20) { continue }
    $baseOffset = 0
  }

  $formattedLine = Format-Packet $buffer $packetLen $baseOffset
  if ($formattedLine) {
    Write-Output $formattedLine
    [Console]::Out.Flush()
  }
}