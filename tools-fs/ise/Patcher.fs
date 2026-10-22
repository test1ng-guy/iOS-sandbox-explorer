// F# IPA patch/inject only (signing is external).
// Device install/list/tunnel live in Device.fs (Netimobiledevice).

module IosSandboxExplorer.Patcher

open System
open System.IO
open System.IO.Compression
open Claunia.PropertyList

let private log (msg: string) = printfn "%s" msg

type IpaPatchResult =
    { OutputPath: string
      AppBundleName: string
      ExecutableName: string }

/// Unpack IPA, inject dylib, patch Info.plist ATS, write entitlements, repack.
let patchIpa (ipaPath: string) (dylibPath: string) (outputPath: string) : Result<IpaPatchResult, string> =
    if not (File.Exists(ipaPath)) then Error $"IPA not found: {ipaPath}"
    elif not (File.Exists(dylibPath)) then Error $"Dylib not found: {dylibPath}"
    else
        let tempDir = Path.Combine(Path.GetTempPath(), "ipa_patch_" + Guid.NewGuid().ToString("N"))
        try
            Directory.CreateDirectory(tempDir) |> ignore
            log $"[*] Unpacking IPA to {tempDir}"
            ZipFile.ExtractToDirectory(ipaPath, tempDir)

            let payloadDir = Path.Combine(tempDir, "Payload")
            if not (Directory.Exists(payloadDir)) then
                Error "No Payload directory found in IPA"
            else
                let apps = Directory.GetDirectories(payloadDir, "*.app") |> Array.toList
                match apps with
                | [] -> Error "No .app bundle found in Payload/"
                | appBundle :: _ ->
                    let appName = Path.GetFileName(appBundle)
                    log $"[+] Found app bundle: {appName}"
                    let infoPlistPath = Path.Combine(appBundle, "Info.plist")
                    if not (File.Exists(infoPlistPath)) then
                        Error "Info.plist not found in app bundle"
                    else
                        let root = PropertyListParser.Parse(FileInfo(infoPlistPath)) :?> NSDictionary
                        let execObj = root.ObjectForKey("CFBundleExecutable")
                        if isNull execObj then
                            Error "CFBundleExecutable not found in Info.plist"
                        else
                            let executableName = execObj.ToString()
                            let binaryPath = Path.Combine(appBundle, executableName)
                            if not (File.Exists(binaryPath)) then
                                Error $"Main binary not found: {binaryPath}"
                            else
                                log $"[+] Main binary: {executableName}"

                                let dylibName = Path.GetFileName(dylibPath)
                                let frameworksDir = Path.Combine(appBundle, "Frameworks")
                                Directory.CreateDirectory(frameworksDir) |> ignore
                                let dylibDst = Path.Combine(frameworksDir, dylibName)
                                File.Copy(dylibPath, dylibDst, true)
                                log $"[+] Copied {dylibName} to Frameworks/"

                                let installName = $"@executable_path/Frameworks/{dylibName}"
                                if not (MachO.inject binaryPath installName) then
                                    Error "Mach-O LC_LOAD_DYLIB injection failed"
                                else
                                    let ats =
                                        match root.ObjectForKey("NSAppTransportSecurity") with
                                        | :? NSDictionary as d -> d
                                        | _ ->
                                            let d = NSDictionary()
                                            root.Add("NSAppTransportSecurity", d :> NSObject)
                                            d
                                    ats.Add("NSAllowsArbitraryLoads", true)
                                    PropertyListParser.SaveAsBinary(root, FileInfo(infoPlistPath))
                                    log "[+] Updated Info.plist: NSAllowsArbitraryLoads = true"

                                    let ent = NSDictionary()
                                    ent.Add("com.apple.security.network.server", true)
                                    ent.Add("com.apple.security.network.client", true)
                                    ent.Add("get-task-allow", true)
                                    let entPath = Path.Combine(tempDir, "entitlements.plist")
                                    PropertyListParser.SaveAsXml(ent, FileInfo(entPath))
                                    log $"[+] Created entitlements: {entPath}"

                                    log $"[*] Repacking IPA to {outputPath}"
                                    if File.Exists(outputPath) then File.Delete(outputPath)
                                    ZipFile.CreateFromDirectory(
                                        Path.Combine(tempDir, "Payload"),
                                        outputPath,
                                        CompressionLevel.Optimal,
                                        includeBaseDirectory = true
                                    )
                                    log $"[+] Patched IPA saved: {outputPath}"
                                    Ok
                                        { OutputPath = outputPath
                                          AppBundleName = appName
                                          ExecutableName = executableName }
        finally
            try
                if Directory.Exists(tempDir) then
                    Directory.Delete(tempDir, true)
                    log "[*] Cleaned up temp files"
            with _ -> ()

/// Offline self-test: Mach-O inject + codesig reclaim + synthetic IPA round-trip.
let selfTest () : int =
    let tmp = Path.Combine(Path.GetTempPath(), "ios-sandbox-patcher-selftest-" + Guid.NewGuid().ToString("N"))
    Directory.CreateDirectory(tmp) |> ignore
    try
        let machoPath = Path.Combine(tmp, "Dummy")
        let padding = 512
        File.WriteAllBytes(machoPath, MachO.createMinimalExecutableWithPadding padding)
        let install = "@executable_path/Frameworks/libShell.dylib"
        if not (MachO.inject machoPath install) then
            eprintfn "self-test-patcher FAIL: inject"
            1
        elif not (MachO.containsLoadDylib (File.ReadAllBytes(machoPath)) "libShell.dylib") then
            eprintfn "self-test-patcher FAIL: load command missing"
            1
        elif not (MachO.inject machoPath install) then
            eprintfn "self-test-patcher FAIL: re-inject (idempotent)"
            1
        else
            let codesigPath = Path.Combine(tmp, "SignedDummy")
            File.WriteAllBytes(codesigPath, MachO.createMinimalExecutableWithOnlyCodeSignature ())
            if not (MachO.inject codesigPath install) then
                eprintfn "self-test-patcher FAIL: codesig reclaim inject"
                1
            elif not (MachO.containsLoadDylib (File.ReadAllBytes(codesigPath)) "libShell.dylib") then
                eprintfn "self-test-patcher FAIL: codesig reclaim missing LC_LOAD_DYLIB"
                1
            else
                let staging = Path.Combine(tmp, "stage")
                let payload = Path.Combine(staging, "Payload", "Dummy.app")
                Directory.CreateDirectory(payload) |> ignore
                File.WriteAllBytes(Path.Combine(payload, "Dummy"), MachO.createMinimalExecutableWithPadding padding)
                let info = NSDictionary()
                info.Add("CFBundleExecutable", NSString("Dummy") :> NSObject)
                info.Add("CFBundleIdentifier", NSString("com.example.dummy") :> NSObject)
                PropertyListParser.SaveAsXml(info, FileInfo(Path.Combine(payload, "Info.plist")))
                let dylibPath = Path.Combine(tmp, "libShell.dylib")
                File.WriteAllBytes(dylibPath, [| 0xCAuy; 0xFEuy; 0xBAuy; 0xBEuy |])
                let ipaPath = Path.Combine(tmp, "Dummy.ipa")
                if File.Exists(ipaPath) then File.Delete(ipaPath)
                ZipFile.CreateFromDirectory(
                    Path.Combine(staging, "Payload"),
                    ipaPath,
                    CompressionLevel.Optimal,
                    includeBaseDirectory = true
                )
                let outIpa = Path.Combine(tmp, "Dummy_patched.ipa")
                match patchIpa ipaPath dylibPath outIpa with
                | Error e ->
                    eprintfn "self-test-patcher FAIL: %s" e
                    1
                | Ok r ->
                    let extract = Path.Combine(tmp, "out")
                    Directory.CreateDirectory(extract) |> ignore
                    ZipFile.ExtractToDirectory(outIpa, extract)
                    let fw = Path.Combine(extract, "Payload", r.AppBundleName, "Frameworks", "libShell.dylib")
                    let bin = Path.Combine(extract, "Payload", r.AppBundleName, r.ExecutableName)
                    if not (File.Exists(fw)) then
                        eprintfn "self-test-patcher FAIL: dylib missing in Frameworks"
                        1
                    elif not (MachO.containsLoadDylib (File.ReadAllBytes(bin)) "libShell.dylib") then
                        eprintfn "self-test-patcher FAIL: patched binary missing LC_LOAD_DYLIB"
                        1
                    else
                        printfn "self-test-patcher OK: Mach-O inject + codesig reclaim + IPA round-trip"
                        0
    finally
        try Directory.Delete(tmp, true) with _ -> ()
