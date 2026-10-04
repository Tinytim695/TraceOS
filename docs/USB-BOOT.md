# TraceOS USB boot test

This guide is for the first TraceOS live-ISO test. Use a spare USB stick because writing the image replaces the USB's existing contents.

## 1. Wait for the GitHub build

The trusted `main` build must finish with these checks passing:

- Host-side CaseStore regression tests and the separate Security Checks workflow
- Final-image checks for every advertised people-OSINT, web-testing, and image-analysis command
- ISO boot-layout report and generated SHA-256 file
- QEMU BIOS boot, graphical Web Testing/Image OSINT screenshots, and synthetic New Case flow
- QEMU packaged-image CLI workflow and build-provenance attestation
- ISO and screenshot artifact uploads

Do not use a failed, cancelled, or still-running workflow artifact. The new Web Testing and Image OSINT pages are verified in QEMU; this is still not a physical USB test. BIOS boot is exercised in QEMU. UEFI is recorded in the ISO layout report, but UEFI and Secure Boot runtime behavior remain separate checks.

## 2. Verify the download

After downloading the ISO and checksum file from the same successful workflow artifact:

On Windows PowerShell:

```powershell
Get-FileHash .\live-image-amd64.hybrid.iso -Algorithm SHA256
Get-Content .\traceos-0.1.0-amd64.iso.sha256
```

The SHA-256 values must match exactly.

## 3. Write the ISO to USB

Use a trusted image-writing utility such as USBImager or balenaEtcher.

Select:

1. the TraceOS ISO
2. the intended USB stick
3. Write/Flash

Do not select an internal disk.

## 4. Boot the Lenovo

Insert the TraceOS USB, restart the machine, and use the Lenovo boot menu key, commonly **F12**, to select the UEFI USB entry.

For the first test choose:

```
TraceOS Amnesic (no persistent storage)
```

Do not create persistence yet.

## 5. First checks inside TraceOS

After the desktop loads:

```bash
traceos status
traceos-session status
```

Expected session result:

```
TraceOS session: amnesic (no persistent storage)
```

Then check the Control Centre, Terminal, Files, Network, Investigation Centre, Web Testing, Image OSINT, and the evidence-handling helpers. Use only synthetic data and targets you own or are explicitly authorized to test.

## Important forensic note

Amnesic mode means the live overlay is not written to a persistence volume. It is not a secure disk-erase function.

TraceOS also is not a hardware write blocker. Use dedicated hardware write-blocking when evidence integrity requires it.
