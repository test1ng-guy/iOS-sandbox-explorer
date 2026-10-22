// Manual LC_LOAD_DYLIB injection (port of tools/patcher.py MachOInjector).
// When header padding is insufficient, reclaim space by stripping LC_CODE_SIGNATURE
// (insert_dylib / lief-class quality for the common signed-binary case — no Python lief).

module IosSandboxExplorer.MachO

open System
open System.IO
open System.Text

let private LC_LOAD_DYLIB = 0x0Cu
let private LC_LOAD_WEAK_DYLIB = 0x18u
let private LC_CODE_SIGNATURE = 0x1Du
let private MH_MAGIC_64 = 0xFEEDFACFu
let private MH_CIGAM_64 = 0xCFFAEDFEu
let private MH_MAGIC_32 = 0xFEEDFACEu
let private MH_CIGAM_32 = 0xCEFAEDFEu
let private FAT_MAGIC = 0xCAFEBABEu
let private FAT_CIGAM = 0xBEBAFECAu

let private readUInt32LE (data: byte[]) (offset: int) =
    BitConverter.ToUInt32(data, offset)

let private readUInt32BE (data: byte[]) (offset: int) =
    uint32 data.[offset] <<< 24
    ||| uint32 data.[offset + 1] <<< 16
    ||| uint32 data.[offset + 2] <<< 8
    ||| uint32 data.[offset + 3]

let private writeUInt32LE (data: byte[]) (offset: int) (value: uint32) =
    let bytes = BitConverter.GetBytes(value)
    Array.Copy(bytes, 0, data, offset, 4)

let private findCString (data: byte[]) (start: int) =
    let mutable endIdx = start
    while endIdx < data.Length && data.[endIdx] <> 0uy do
        endIdx <- endIdx + 1
    Encoding.UTF8.GetString(data, start, endIdx - start)

/// Remove LC_CODE_SIGNATURE from a thin slice to free load-command padding. Returns bytes reclaimed.
let private stripCodeSignature (data: byte[]) (baseOffset: int) (hdr: int) : int =
    let ncmds = int (readUInt32LE data (baseOffset + 16))
    let sizeofcmds = int (readUInt32LE data (baseOffset + 20))
    let cmdsStart = baseOffset + hdr
    let mutable off = cmdsStart
    let mutable foundAt = -1
    let mutable foundSize = 0
    for _ in 1..ncmds do
        if off + 8 > data.Length then ()
        else
            let cmd = readUInt32LE data off
            let cmdsize = int (readUInt32LE data (off + 4))
            if foundAt < 0 && cmd = LC_CODE_SIGNATURE && cmdsize > 0 then
                foundAt <- off
                foundSize <- cmdsize
            if cmdsize > 0 then
                off <- off + cmdsize

    if foundAt < 0 || foundSize <= 0 then 0
    else
        let cmdsEnd = cmdsStart + sizeofcmds
        let after = foundAt + foundSize
        let tailLen = cmdsEnd - after
        if tailLen > 0 then
            Array.Copy(data, after, data, foundAt, tailLen)
        // Zero the vacated tail of the command region (becomes padding).
        Array.Clear(data, foundAt + tailLen, foundSize)
        writeUInt32LE data (baseOffset + 16) (uint32 (ncmds - 1))
        writeUInt32LE data (baseOffset + 20) (uint32 (sizeofcmds - foundSize))
        printfn "[*] Stripped LC_CODE_SIGNATURE (%d bytes) to free inject space" foundSize
        foundSize

let private buildLoadDylibCommand (dylibInstallName: string) : byte[] =
    let nameBytes = Encoding.UTF8.GetBytes(dylibInstallName + "\u0000")
    use ms = new MemoryStream()
    use bw = new BinaryWriter(ms)
    bw.Write(LC_LOAD_DYLIB)
    bw.Write(0u) // placeholder cmdsize
    bw.Write(24u) // name offset from start of command
    bw.Write(2u) // timestamp
    bw.Write(0x00010000u) // current_version 1.0.0
    bw.Write(0x00010000u) // compat_version 1.0.0
    bw.Write(nameBytes)
    while ms.Length % 8L <> 0L do
        bw.Write(0uy)
    let cmdBody = ms.ToArray()
    writeUInt32LE cmdBody 4 (uint32 cmdBody.Length)
    cmdBody

let private availablePadding (data: byte[]) (cmdsEnd: int) (needed: int) =
    let mutable available = 0
    let mutable check = cmdsEnd
    while check < data.Length && data.[check] = 0uy && available < needed do
        available <- available + 1
        check <- check + 1
    available

/// Inject into a thin Mach-O slice starting at baseOffset. Mutates data in place.
let injectThin (data: byte[]) (baseOffset: int) (dylibInstallName: string) : bool =
    let magic = readUInt32LE data baseOffset
    let headerSize =
        if magic = MH_MAGIC_64 || magic = MH_CIGAM_64 then Some 32
        elif magic = MH_MAGIC_32 || magic = MH_CIGAM_32 then Some 28
        else None

    match headerSize with
    | None ->
        printfn "[!] Unknown Mach-O magic: 0x%X" magic
        false
    | Some hdr ->
        let ncmds0 = int (readUInt32LE data (baseOffset + 16))

        // Walk existing load commands for idempotent re-inject.
        let mutable cmdOffset = baseOffset + hdr
        let mutable alreadyInjected = false
        for _ in 1..ncmds0 do
            if not alreadyInjected && cmdOffset + 8 <= data.Length then
                let cmd = readUInt32LE data cmdOffset
                let cmdsize = int (readUInt32LE data (cmdOffset + 4))
                if cmdsize > 0 && (cmd = LC_LOAD_DYLIB || cmd = LC_LOAD_WEAK_DYLIB) then
                    let nameOff = int (readUInt32LE data (cmdOffset + 8))
                    let existing = findCString data (cmdOffset + nameOff)
                    if existing.Contains(dylibInstallName) then
                        printfn "[*] Already injected: %s" existing
                        alreadyInjected <- true
                if cmdsize > 0 then
                    cmdOffset <- cmdOffset + cmdsize

        if alreadyInjected then true
        else
            let cmdBody = buildLoadDylibCommand dylibInstallName
            let newCmdsize = cmdBody.Length

            let tryWrite () =
                let ncmds = int (readUInt32LE data (baseOffset + 16))
                let sizeofcmds = int (readUInt32LE data (baseOffset + 20))
                let cmdsEnd = baseOffset + hdr + sizeofcmds
                let available = availablePadding data cmdsEnd newCmdsize
                if available < newCmdsize then
                    false
                else
                    Array.Copy(cmdBody, 0, data, cmdsEnd, newCmdsize)
                    writeUInt32LE data (baseOffset + 16) (uint32 (ncmds + 1))
                    writeUInt32LE data (baseOffset + 20) (uint32 (sizeofcmds + newCmdsize))
                    printfn "[+] Injected LC_LOAD_DYLIB: %s" dylibInstallName
                    true

            if tryWrite () then true
            else
                // lief / insert_dylib class: reclaim codesig command space, then retry once.
                let reclaimed = stripCodeSignature data baseOffset hdr
                if reclaimed > 0 && tryWrite () then true
                else
                    let sizeofcmds = int (readUInt32LE data (baseOffset + 20))
                    let cmdsEnd = baseOffset + hdr + sizeofcmds
                    let available = availablePadding data cmdsEnd newCmdsize
                    printfn "[!] Not enough space for injection. Need %d bytes, have %d" newCmdsize available
                    false

let private injectFat (data: byte[]) (dylibInstallName: string) : bool =
    let magic = readUInt32BE data 0
    let swap = magic = FAT_CIGAM
    let nfat =
        if swap then int (readUInt32LE data 4)
        else int (readUInt32BE data 4)
    printfn "[*] FAT binary with %d slices" nfat
    let mutable allOk = true
    for i in 0 .. nfat - 1 do
        let archOffset = 8 + i * 20
        let offset =
            if swap then int (readUInt32LE data (archOffset + 8))
            else int (readUInt32BE data (archOffset + 8))
        printfn "[*] Processing slice at offset %d" offset
        if not (injectThin data offset dylibInstallName) then
            allOk <- false
    allOk

/// Inject LC_LOAD_DYLIB into a Mach-O file on disk (thin or FAT).
let inject (binaryPath: string) (dylibInstallName: string) : bool =
    let data = File.ReadAllBytes(binaryPath)
    let magicBE = readUInt32BE data 0
    let ok =
        if magicBE = FAT_MAGIC || magicBE = FAT_CIGAM then
            injectFat data dylibInstallName
        else
            injectThin data 0 dylibInstallName
    if ok then
        File.WriteAllBytes(binaryPath, data)
        printfn "[+] Saved modified binary: %s" binaryPath
    ok

/// Build a minimal thin arm64 MH_EXECUTE with zero padding for self-tests.
let createMinimalExecutableWithPadding (padding: int) : byte[] =
    let headerSize = 32
    let data = Array.zeroCreate (headerSize + padding)
    writeUInt32LE data 0 MH_MAGIC_64
    writeUInt32LE data 4 0x0100000cu // CPU_TYPE_ARM64
    writeUInt32LE data 8 0u
    writeUInt32LE data 12 2u // MH_EXECUTE
    writeUInt32LE data 16 0u // ncmds
    writeUInt32LE data 20 0u // sizeofcmds
    writeUInt32LE data 24 0u
    writeUInt32LE data 28 0u
    data

/// Minimal executable whose only load command is an oversized LC_CODE_SIGNATURE and no free
/// padding after sizeofcmds — used to verify codesig reclaim unlocks inject space.
let createMinimalExecutableWithOnlyCodeSignature () : byte[] =
    let headerSize = 32
    // Real LC_CODE_SIGNATURE cmds are 16 bytes; use a larger cmdsize so reclaim frees
    // enough room for a typical LC_LOAD_DYLIB path (self-test of the reclaim path).
    let sigCmdSize = 128
    let data = Array.zeroCreate (headerSize + sigCmdSize)
    writeUInt32LE data 0 MH_MAGIC_64
    writeUInt32LE data 4 0x0100000cu
    writeUInt32LE data 8 0u
    writeUInt32LE data 12 2u
    writeUInt32LE data 16 1u // ncmds
    writeUInt32LE data 20 (uint32 sigCmdSize) // sizeofcmds
    writeUInt32LE data 24 0u
    writeUInt32LE data 28 0u
    writeUInt32LE data headerSize LC_CODE_SIGNATURE
    writeUInt32LE data (headerSize + 4) (uint32 sigCmdSize)
    writeUInt32LE data (headerSize + 8) 0u // dataoff
    writeUInt32LE data (headerSize + 12) 0u // datasize
    data

/// True if any LC_LOAD_DYLIB name contains the needle.
let containsLoadDylib (data: byte[]) (needle: string) : bool =
    let magic = readUInt32LE data 0
    let hdr =
        if magic = MH_MAGIC_64 || magic = MH_CIGAM_64 then 32
        elif magic = MH_MAGIC_32 || magic = MH_CIGAM_32 then 28
        else 0
    if hdr = 0 then false
    else
        let ncmds = int (readUInt32LE data 16)
        let mutable off = hdr
        let mutable found = false
        for _ in 1..ncmds do
            if not found && off + 8 <= data.Length then
                let cmd = readUInt32LE data off
                let cmdsize = int (readUInt32LE data (off + 4))
                if cmdsize > 0 && (cmd = LC_LOAD_DYLIB || cmd = LC_LOAD_WEAK_DYLIB) then
                    let nameOff = int (readUInt32LE data (off + 8))
                    let name = findCString data (off + nameOff)
                    if name.Contains(needle) then found <- true
                if cmdsize > 0 then off <- off + cmdsize
        found
