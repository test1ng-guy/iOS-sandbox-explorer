// F# TCP shell client + SCP download (FILE; lines). Replaces former client.py.

module IosSandboxExplorer.Client

open System
open System.IO
open System.Net.Sockets
open System.Text

/// Parse SCP body after "SCP:host_path;" — lines are "FILE;relative_path;base64".
/// Creates parent directories only when the relative path has a directory component
/// (fixes Python client bug: makedirs("") on bare filenames).
let parseScpResponse (response: string) (hostBasePath: string) : string list =
    let messages = ResizeArray<string>()

    for line in response.Replace("\r\n", "\n").Split('\n') do
        let trimmed = line.TrimEnd('\r')
        if trimmed.StartsWith("FILE;", StringComparison.Ordinal) then
            let parts = trimmed.Split([| ';' |], 3)
            if parts.Length = 3 then
                let relativePath = parts[1]
                let b64Data = parts[2]
                try
                    let fileData = Convert.FromBase64String(b64Data)
                    let fullPath = Path.Combine(hostBasePath, relativePath)
                    let dir = Path.GetDirectoryName(fullPath)
                    if not (String.IsNullOrEmpty(dir)) then
                        Directory.CreateDirectory(dir) |> ignore
                    File.WriteAllBytes(fullPath, fileData)
                    messages.Add($"Saved: {fullPath}")
                with ex ->
                    messages.Add($"Error saving {relativePath}: {ex.Message}")
            else
                if not (String.IsNullOrWhiteSpace(trimmed)) then
                    messages.Add($"Unknown SCP line: {trimmed}")
        elif not (String.IsNullOrWhiteSpace(trimmed)) then
            messages.Add($"Unknown SCP line: {trimmed}")

    messages |> Seq.toList

let private handleResponse (responseStr: string) : int =
    if responseStr.StartsWith("SCP:", StringComparison.Ordinal) then
        match responseStr.Split([| ';' |], 2) with
        | [| scpHost; rest |] ->
            let hostPath = scpHost.Substring(4) // drop "SCP:"
            printfn "Downloading to: %s" hostPath
            for msg in parseScpResponse rest hostPath do
                printfn "%s" msg
            0
        | _ ->
            printfn "Invalid SCP response format"
            1
    else
        printf "%s" responseStr
        if not (responseStr.EndsWith("\n")) then printfn ""
        0

/// Send one command to the shell server; print response or save SCP files.
let runCommand (host: string) (port: int) (command: string) : int =
    try
        use client = new TcpClient()
        client.Connect(host, port)
        use stream = client.GetStream()

        let payload = Encoding.UTF8.GetBytes(command + "\n")
        stream.Write(payload, 0, payload.Length)

        use ms = new MemoryStream()
        let buffer = Array.zeroCreate 4096
        let mutable reading = true
        while reading do
            let n = stream.Read(buffer, 0, buffer.Length)
            if n = 0 then reading <- false
            else ms.Write(buffer, 0, n)

        let responseStr = Encoding.UTF8.GetString(ms.ToArray())
        handleResponse responseStr
    with ex ->
        eprintfn "Error: %s" ex.Message
        1

/// Offline checks for SCP parsing (no device required).
let selfTest () : int =
    let tmp = Path.Combine(Path.GetTempPath(), "ios-sandbox-explorer-client-selftest-" + Guid.NewGuid().ToString("N"))
    Directory.CreateDirectory(tmp) |> ignore
    try
        // Bare filename — must not throw on empty dirname
        let b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("hello"))
        let msgs = parseScpResponse $"FILE;hello.txt;{b64}" tmp
        let path = Path.Combine(tmp, "hello.txt")
        if not (File.Exists(path)) then
            eprintfn "self-test FAIL: bare file not written"
            1
        elif not (File.ReadAllText(path) = "hello") then
            eprintfn "self-test FAIL: bare file content mismatch"
            1
        else
            // Nested relative path
            let b642 = Convert.ToBase64String(Encoding.UTF8.GetBytes("nested"))
            let _ = parseScpResponse $"FILE;sub/dir/x.bin;{b642}" tmp
            let nested = Path.Combine(tmp, "sub", "dir", "x.bin")
            if not (File.Exists(nested)) then
                eprintfn "self-test FAIL: nested file not written"
                1
            else
                printfn "self-test OK: SCP bare + nested paths"
                for m in msgs do printfn "  %s" m
                0
    finally
        try Directory.Delete(tmp, true) with _ -> ()
