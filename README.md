# TraceOS

TraceOS is a Debian-based Linux desktop project focused on digital investigation, forensics, privacy-first tooling, and a local AI terminal assistant.

## Project goals

- Proper graphical Linux desktop for everyday use
- Native investigation and forensic tooling
- Local-first case management
- Terminal-first AI assistant support
- Reproducible ISO builds
- No telemetry or automatic evidence uploads

## Current milestone

**0.1.0 foundation**

The first milestone establishes a bootable Debian 13 "trixie" XFCE desktop image with a TraceOS launcher, core system utilities, OSINT, web-testing and image-analysis workflows, and GitHub Actions validation for the installed tools.

## Build locally

On a Debian-based build host:

```bash
sudo apt update
sudo apt install -y live-build debootstrap xorriso
./build.sh
```

The resulting image is:

```
live-image-amd64.hybrid.iso
```

## Pre-USB validation

Every candidate build runs the host-side case regressions, security checks, installed-tool checks against the final image, ISO layout and SHA-256 validation, and QEMU BIOS boot. The graphical QEMU smoke test captures the real Dashboard, Web Testing and Image OSINT pages, then verifies synthetic New Case creation. It does not start scanners or make external OSINT lookups. CI publishes the screenshots separately from the ISO.

Before flashing a downloaded ISO, verify its SHA-256 against the accompanying `traceos-0.1.0-amd64.iso.sha256` file. Flashing the image to a USB device is destructive to the selected device, so identify the target device carefully and verify the checksum before writing it.

The first physical USB boot should be treated as a hardware validation pass. Check Wi-Fi/networking, display resolution, audio, USB storage detection, Bluetooth where available, read-only evidence mounting, suspend/shutdown behaviour, and the default amnesic session before relying on the image for real work.

## Demo Lab

Demo Lab always creates a separate synthetic case containing clearly marked demonstration evidence. It does not inject demo material into the currently selected case.

## Safety model

TraceOS is designed for legitimate administration, incident response, forensics, CTFs, and security testing on systems you are authorized to assess. Network and security utilities are user-invoked rather than automatically run against external targets.

## Session model

TraceOS provides explicit live session modes at boot:

- **Amnesic (no persistent storage)**: boots with `nopersistence`. The live overlay is not written to a persistence volume. This is not a secure disk-erase feature.
- **Persistent**: boots with `persistence` and looks for a live-boot persistence volume.
- **Persistent (Encrypted LUKS)**: boots with `persistence persistence-encryption=luks` and permits LUKS persistence.
- **Persistent from USB** and **Encrypted Persistent from USB** are available under advanced boot options.

For persistence, live-boot expects a persistence volume labelled `persistence` (or another explicitly selected label) with a `persistence.conf` file. The volume can be prepared separately on an ext4 filesystem or another supported medium. TraceOS does not automatically partition, format, encrypt, or select a user's disks.

The default boot entry is Amnesic, deliberately making the safest session behaviour the automatic path. The Control Centre reports the active session mode.

A separate recovery/factory-reset workflow will be developed for installed systems. It will require explicit confirmation and will distinguish ordinary reset from hardware/device secure-erase operations.

## Forensic desktop safety

TraceOS disables desktop auto-mount/auto-open behaviour at session start and disables Thunar thumbnails by default. TraceOS disables Thunar volume-management auto-mount behaviour and the desktop auto-mount/auto-open settings. For deliberate evidence access, `traceos-evidence-mount /dev/<partition>` mounts a block-device partition read-only with `nosuid,nodev,noexec`; ext2/3/4 also use `noload` to prevent journal replay. Use `traceos-evidence-umount` when finished. These helpers do not provide hardware write blocking.

## Updates

TraceOS includes Debian's `package-update-indicator`, intended for Xfce desktops, so normal Debian updates can be reported to the user. Use `traceos update check` to refresh package metadata and inspect available upgrades, or `traceos update` for a user-approved Debian full upgrade. Bundled third-party OSINT tools stay pinned until a tested TraceOS update replaces them. `traceos update check` shows the installed stack and Debian updates; new ISO builds are the controlled path for changing bundled third-party versions.

## OSINT workbench

The Investigation Centre and `traceos osint` expose six people/domain OSINT commands: Sherlock 0.16.2 and Maigret 0.6.6 for usernames, h8mail 2.5.6 for email-oriented lookups, Blackbird pinned to upstream commit `b45505080ef51bb3ef52dc29879ee6bef31e5b94`, plus WHOIS and DNS. The image build checks all six command paths and local help for the four Python tools. External lookups start only after the user presses Start.

## Web Testing

The Web Testing page provides Nmap, WhatWeb, Nikto, Gobuster, SQLmap, OWASP ZAP, and Metasploit. The active command-line checks require an authorization checkbox and a per-run confirmation. OWASP ZAP 2.17.0 is installed from its Linux archive after a SHA-256 check and opens in its own window; it receives no target and starts no scan automatically. Set and confirm scope inside ZAP before starting a scan. The Debian tools WhatWeb, Nikto, Gobuster, and SQLmap come from Debian 13 repositories; Gobuster uses the packaged dirb common wordlist.

Metasploit Framework is pinned to Rapid7 package version `6.5.3~20260818061200~1rapid7-1`. TraceOS opens its console in a terminal without selecting a target, module, or exploit. SQLmap opens interactively; the user reviews its prompts. Metasploit itself does not enforce a target scope, so only use its console within an authorized assessment. The Rapid7 repository is used during the image build and removed from the live image after installation.

## Image OSINT

Image OSINT runs locally: it computes SHA-256, identifies MIME type and image dimensions, extracts metadata with ExifTool, and attempts local OCR with Tesseract. The GUI does not upload selected images. Google Lens, Bing Visual Search, and TinEye are optional browser handoffs; TraceOS displays an external-service warning and the user must choose and submit the image on that site.

## Security engineering

The ISO build uses Debian security repositories over HTTPS and pins the live-build source to a known upstream revision. Pull requests are handled by a separate read-only security-check workflow instead of executing untrusted PR code in the privileged ISO build. Static checks include ShellCheck, Bandit, Python compilation, and a tracked-secret pattern scan.

Before a public 1.0 release, TraceOS must also pass VM/hardware boot tests, dependency/package audits, removable-media tests, privilege/service checks, evidence-handling tests, and signed-release verification.

## Roadmap

- Desktop foundation
- TraceOS control centre
- CaseForge integration
- ShellSieve integration
- TraceLock integration
- DNAProcess integration
- Expanded image-forensics workflows
- Additional people and domain OSINT providers
- Local Ari/llama.cpp integration
- Installer and signed releases
