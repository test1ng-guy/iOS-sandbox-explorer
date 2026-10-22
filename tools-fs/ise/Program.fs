// CLI — F# host tools (client + patch + device). Prefer the repo-root ./ise launcher.
//
//   ise <shell-command> [--host HOST] [--port PORT]
//   ise client <shell-command> [--host HOST] [--port PORT]
//   ise patch --ipa FILE --dylib FILE [-o OUT]
//   ise devices
//   ise install --ipa FILE [--udid UDID]
//   ise tunnel [--local-port N] [--remote-port N] [--udid UDID]
//   ise full --ipa FILE --dylib FILE [-o OUT] [--install] [--udid UDID]
//   ise --self-test
//   ise --self-test-patcher
//   ise --self-test-devices

module Program

open System
open System.IO
open IosSandboxExplorer

let private usage () =
    printfn "ise — F# host tooling (client + IPA patch + device)"
    printfn ""
    printfn "Client:"
    printfn "  ise <command> [--host HOST] [--port PORT]"
    printfn "  ise client <command> [--host HOST] [--port PORT]"
    printfn "  ise --self-test"
    printfn ""
    printfn "Patch (dylib inject only — sign externally):"
    printfn "  ise patch --ipa FILE --dylib FILE [-o OUT.ipa]"
    printfn "  ise --self-test-patcher"
    printfn ""
    printfn "Device (Netimobiledevice):"
    printfn "  ise devices"
    printfn "  ise install --ipa FILE [--udid UDID]"
    printfn "  ise tunnel [--local-port N] [--remote-port N] [--udid UDID]"
    printfn "  ise full --ipa FILE --dylib FILE [-o OUT] [--install] [--udid UDID]"
    printfn "  ise --self-test-devices"
    printfn ""
    printfn "IPA signing is out of scope (use feather / ipasigner / Sideloadly / zsign)."

let private parseClientFlags (argv: string[]) (start: int) =
    let mutable host = "localhost"
    let mutable port = 8080
    let mutable command: string option = None
    let mutable i = start
    let mutable err: string option = None
    while i < argv.Length && err.IsNone do
        match argv[i] with
        | "--host" when i + 1 < argv.Length ->
            host <- argv[i + 1]
            i <- i + 2
        | "--port" when i + 1 < argv.Length ->
            match Int32.TryParse(argv[i + 1]) with
            | true, p ->
                port <- p
                i <- i + 2
            | _ -> err <- Some $"Invalid --port: {argv[i + 1]}"
        | flag when flag.StartsWith("-") -> err <- Some $"Unknown option: {flag}"
        | cmd ->
            match command with
            | Some _ -> err <- Some "Only one shell command is allowed"
            | None ->
                command <- Some cmd
                i <- i + 1
    match err, command with
    | Some e, _ -> Error e
    | None, None -> Error "missing shell command"
    | None, Some c -> Ok(c, host, port)

type private PatchArgs =
    { Ipa: string
      Dylib: string
      Output: string
      Install: bool
      Udid: string option }

let private defaultPatchedOutput (ipa: string) =
    let dir = Path.GetDirectoryName(ipa)
    let name = Path.GetFileNameWithoutExtension(ipa) + "_patched.ipa"
    if String.IsNullOrEmpty(dir) then name else Path.Combine(dir, name)

let private parsePatchLikeFlags (argv: string[]) (start: int) (allowInstall: bool) =
    let mutable ipa: string option = None
    let mutable dylib: string option = None
    let mutable output: string option = None
    let mutable install = false
    let mutable udid: string option = None
    let mutable i = start
    let mutable err: string option = None
    while i < argv.Length && err.IsNone do
        match argv[i] with
        | "--ipa" when i + 1 < argv.Length ->
            ipa <- Some argv[i + 1]
            i <- i + 2
        | "--dylib" when i + 1 < argv.Length ->
            dylib <- Some argv[i + 1]
            i <- i + 2
        | "--output" | "-o" when i + 1 < argv.Length ->
            output <- Some argv[i + 1]
            i <- i + 2
        | "--udid" when i + 1 < argv.Length ->
            udid <- Some argv[i + 1]
            i <- i + 2
        | "--install" when allowInstall ->
            install <- true
            i <- i + 1
        | "--use-lief" ->
            // Accepted for CLI compatibility with former Python patcher; F# inject
            // already reclaim codesig space automatically (no separate lief dep).
            i <- i + 1
        | flag when flag.StartsWith("-") -> err <- Some $"Unknown option: {flag}"
        | other -> err <- Some $"Unexpected argument: {other}"
    match err with
    | Some e -> Error e
    | None ->
        match ipa, dylib with
        | Some i, Some d ->
            Ok
                { Ipa = i
                  Dylib = d
                  Output = defaultArg output (defaultPatchedOutput i)
                  Install = install
                  Udid = udid }
        | None, _ -> Error "requires --ipa"
        | _, None -> Error "requires --dylib"

let private parseInstallFlags (argv: string[]) (start: int) =
    let mutable ipa: string option = None
    let mutable udid: string option = None
    let mutable i = start
    let mutable err: string option = None
    while i < argv.Length && err.IsNone do
        match argv[i] with
        | "--ipa" when i + 1 < argv.Length ->
            ipa <- Some argv[i + 1]
            i <- i + 2
        | "--udid" when i + 1 < argv.Length ->
            udid <- Some argv[i + 1]
            i <- i + 2
        | flag when flag.StartsWith("-") -> err <- Some $"Unknown install option: {flag}"
        | other -> err <- Some $"Unexpected argument: {other}"
    match err, ipa with
    | Some e, _ -> Error e
    | None, None -> Error "install requires --ipa"
    | None, Some p -> Ok(p, udid)

let private parseTunnelFlags (argv: string[]) (start: int) =
    let mutable localPort = 8080
    let mutable remotePort = 8080
    let mutable udid: string option = None
    let mutable i = start
    let mutable err: string option = None
    while i < argv.Length && err.IsNone do
        match argv[i] with
        | "--local-port" when i + 1 < argv.Length ->
            match Int32.TryParse(argv[i + 1]) with
            | true, p ->
                localPort <- p
                i <- i + 2
            | _ -> err <- Some $"Invalid --local-port: {argv[i + 1]}"
        | "--remote-port" when i + 1 < argv.Length ->
            match Int32.TryParse(argv[i + 1]) with
            | true, p ->
                remotePort <- p
                i <- i + 2
            | _ -> err <- Some $"Invalid --remote-port: {argv[i + 1]}"
        | "--udid" when i + 1 < argv.Length ->
            udid <- Some argv[i + 1]
            i <- i + 2
        | flag when flag.StartsWith("-") -> err <- Some $"Unknown tunnel option: {flag}"
        | other -> err <- Some $"Unexpected argument: {other}"
    match err with
    | Some e -> Error e
    | None -> Ok(localPort, remotePort, udid)

let private runPatch (args: PatchArgs) : int =
    match Patcher.patchIpa args.Ipa args.Dylib args.Output with
    | Ok r ->
        printfn ""
        printfn "[+] PATCHED IPA READY (unsigned)"
        printfn "    Output: %s" r.OutputPath
        printfn "    Sign externally (feather / ipasigner / Sideloadly / zsign), then install."
        if args.Install then
            printfn ""
            printfn "[*] IPA is unsigned — sign with an external tool before device install."
            printfn "[*] Attempting install anyway (--install was set)..."
            Device.installIpa r.OutputPath args.Udid
        else
            0
    | Error e ->
        eprintfn "[!] %s" e
        1

[<EntryPoint>]
let main argv =
    if argv.Length = 0 then
        usage ()
        1
    else
        match argv[0] with
        | "--help" | "-h" ->
            usage ()
            0
        | "--self-test" -> Client.selfTest ()
        | "--self-test-patcher" -> Patcher.selfTest ()
        | "--self-test-devices" -> Device.selfTest ()
        | "patch" ->
            match parsePatchLikeFlags argv 1 false with
            | Error e ->
                eprintfn "Error: %s" e
                usage ()
                1
            | Ok args -> runPatch { args with Install = false }
        | "full" ->
            match parsePatchLikeFlags argv 1 true with
            | Error e ->
                eprintfn "Error: %s" e
                usage ()
                1
            | Ok args ->
                printfn "[*] IPA will be unsigned — sign externally before a successful device install."
                runPatch args
        | "devices" ->
            if argv.Length > 1 then
                eprintfn "Error: devices takes no arguments"
                usage ()
                1
            else
                Device.listDevices ()
        | "install" ->
            match parseInstallFlags argv 1 with
            | Error e ->
                eprintfn "Error: %s" e
                usage ()
                1
            | Ok(ipa, udid) -> Device.installIpa ipa udid
        | "tunnel" ->
            match parseTunnelFlags argv 1 with
            | Error e ->
                eprintfn "Error: %s" e
                usage ()
                1
            | Ok(localPort, remotePort, udid) -> Device.startTunnel localPort remotePort udid
        | "client" ->
            match parseClientFlags argv 1 with
            | Error e ->
                eprintfn "Error: %s" e
                usage ()
                1
            | Ok(cmd, host, port) -> Client.runCommand host port cmd
        | _ ->
            // Backward-compatible: first token is the shell command (Phase 7 CLI).
            match parseClientFlags argv 0 with
            | Error e ->
                eprintfn "Error: %s" e
                usage ()
                1
            | Ok(cmd, host, port) -> Client.runCommand host port cmd
