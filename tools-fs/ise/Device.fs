// iOS device helpers via Netimobiledevice (pymobiledevice3 / ideviceinstaller / iproxy stand-in).
//
//   devices              — list usbmux devices
//   install --ipa FILE   — install IPA via installation_proxy
//   tunnel               — TCP forward localhost:local -> device:remote (iproxy-class)

module IosSandboxExplorer.Device

open System
open System.IO
open System.Net
open System.Net.Sockets
open System.Threading
open System.Threading.Tasks
open Netimobiledevice
open Netimobiledevice.InstallationProxy
open Netimobiledevice.Usbmuxd

let private log (msg: string) = printfn "%s" msg

/// List connected devices (usbmux). Prints UDIDs; returns 0 even when none found.
let listDevices () : int =
    try
        let devices = Usbmux.GetDeviceList()
        if devices.Count = 0 then
            log "[*] No iOS devices connected."
            0
        else
            log $"[+] Found {devices.Count} device(s):"
            devices
            |> Seq.iteri (fun i (dev: UsbmuxdDevice) ->
                let conn =
                    match dev.ConnectionType with
                    | UsbmuxdConnectionType.Usb -> "USB"
                    | UsbmuxdConnectionType.Network -> "Network"
                    | _ -> "Unknown"
                log $"  [{i}] UDID: {dev.Serial} ({conn})")
            0
    with ex ->
        eprintfn "[!] Failed to list devices: %s" ex.Message
        eprintfn "    Ensure usbmuxd / Apple Mobile Device Support is running and the device is trusted."
        1

/// Install IPA onto a connected device via Netimobiledevice InstallationProxyService.
let installIpa (ipaPath: string) (udid: string option) : int =
    if not (File.Exists(ipaPath)) then
        eprintfn "[!] IPA not found: %s" ipaPath
        1
    else
        try
            let serial = defaultArg udid ""
            let target =
                match udid with
                | Some u when not (String.IsNullOrWhiteSpace(u)) -> $": {u.Substring(0, min 12 u.Length)}..."
                | _ -> ""
            log $"[*] Installing on device{target}"
            use lockdown = MobileDevice.CreateUsingUsbmux(serial = serial)
            use proxy = new InstallationProxyService(lockdown)
            let progress =
                Progress<int>(fun p ->
                    Console.Write($"\r[*] Installing: {p}%%")
                    Console.Out.Flush())
            proxy.Install(ipaPath, CancellationToken.None, progress = progress).GetAwaiter().GetResult()
            Console.WriteLine()
            log "[+] Installation complete!"
            0
        with ex ->
            Console.WriteLine()
            eprintfn "[!] Install failed: %s" ex.Message
            1

let private pipeAsync (src: NetworkStream) (dst: NetworkStream) (ct: CancellationToken) : Task =
    task {
        let buffer = Array.zeroCreate 65536
        try
            while not ct.IsCancellationRequested do
                let! n = src.ReadAsync(buffer.AsMemory(0, buffer.Length), ct)
                if n = 0 then return ()
                else
                    do! dst.WriteAsync(buffer.AsMemory(0, n), ct)
                    do! dst.FlushAsync(ct)
        with
        | :? OperationCanceledException -> ()
        | :? IOException -> ()
        | :? ObjectDisposedException -> ()
    }

/// Select a usbmux device: explicit UDID, else first USB, else first listed.
let private selectDevice (udid: string option) : Result<UsbmuxdDevice, string> =
    try
        match udid with
        | Some u when not (String.IsNullOrWhiteSpace(u)) ->
            match Usbmux.GetDevice(u) with
            | null -> Error $"No device with UDID: {u}"
            | d -> Ok d
        | _ ->
            let devices = Usbmux.GetDeviceList()
            if devices.Count = 0 then Error "No iOS devices connected."
            else
                let usb =
                    devices
                    |> Seq.tryFind (fun (d: UsbmuxdDevice) -> d.ConnectionType = UsbmuxdConnectionType.Usb)
                match usb with
                | Some d -> Ok d
                | None -> Ok devices[0]
    with ex ->
        Error ex.Message

/// USB TCP tunnel: listen on localPort, forward each connection to device remotePort via usbmux.
/// Blocks until Ctrl+C (foreground; better than Python's fire-and-forget Popen of iproxy).
let startTunnel (localPort: int) (remotePort: int) (udid: string option) : int =
    if localPort < 1 || localPort > 65535 || remotePort < 1 || remotePort > 65535 then
        eprintfn "[!] Ports must be in 1..65535"
        1
    else
        match selectDevice udid with
        | Error e ->
            eprintfn "[!] %s" e
            1
        | Ok device ->
            log $"[*] Starting USB tunnel: localhost:{localPort} -> device:{remotePort}"
            log $"[*] Device: {device.Serial}"
            try
                let listener = new TcpListener(IPAddress.Loopback, localPort)
                listener.Start()
                log $"[+] Tunnel active: localhost:{localPort} (Ctrl+C to stop)"

                use cts = new CancellationTokenSource()
                Console.CancelKeyPress.Add(fun args ->
                    args.Cancel <- true
                    cts.Cancel())

                let remotePortU = uint16 remotePort
                try
                    while not cts.IsCancellationRequested do
                        let acceptTask = listener.AcceptTcpClientAsync()
                        let completed =
                            try
                                acceptTask.Wait(cts.Token)
                                true
                            with :? OperationCanceledException -> false
                        if completed then
                            let client = acceptTask.Result
                            Task.Run(fun () ->
                                try
                                    use client = client
                                    use localStream = client.GetStream()
                                    use remoteSock = device.Connect(remotePortU)
                                    use remoteStream = new NetworkStream(remoteSock, ownsSocket = true)
                                    use linkCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token)
                                    let t1 = pipeAsync localStream remoteStream linkCts.Token
                                    let t2 = pipeAsync remoteStream localStream linkCts.Token
                                    let doneIdx = Task.WaitAny([| t1; t2 |], cts.Token)
                                    linkCts.Cancel()
                                    ignore doneIdx
                                with
                                | :? OperationCanceledException -> ()
                                | ex -> eprintfn "[!] Tunnel connection error: %s" ex.Message)
                            |> ignore
                finally
                    listener.Stop()
                log "[*] Tunnel stopped."
                0
            with ex ->
                eprintfn "[!] Tunnel failed: %s" ex.Message
                eprintfn "    Ensure usbmuxd is running and the device is paired/trusted."
                1

/// Offline self-test: listDevices must not crash when usbmux is absent (returns 0 or 1 with message).
let selfTest () : int =
    try
        // Exercise list path; absence of usbmuxd is OK.
        let code = listDevices ()
        if code = 0 || code = 1 then
            printfn "self-test-devices OK: listDevices returned %d" code
            0
        else
            eprintfn "self-test-devices FAIL: unexpected exit %d" code
            1
    with ex ->
        eprintfn "self-test-devices FAIL: %s" ex.Message
        1
