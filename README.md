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

**Automated candidate status (14 October 2026):** The integrated dependency/CI fix passed Build #456 and Security Checks #407, including ISO validation, QEMU live boot, graphical UI screenshots, synthetic case creation, CLI workflow, provenance and artifact uploads. The post-merge `main` ISO build is the release candidate to download; physical USB boot remains unverified until tested on hardware.

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

The Investigation Centre and `traceos osint` expose the bundled people and domain tools. External lookups start only after the user presses Start.

## Web Testing

The Web Testing page provides Nmap, WhatWeb, Nikto, Gobuster, SQLmap, OWASP ZAP, and Metasploit. The active command-line checks require an authorization checkbox and a per-run confirmation. OWASP ZAP 2.17.0 is installed from its Linux archive after a SHA-256 check and opens in its own window; it receives no target and starts no scan automatically. Set and confirm scope inside ZAP before starting a scan. The Debian tools WhatWeb, Nikto, Gobuster, and SQLmap come from Debian 13 repositories; Gobuster uses the packaged dirb common wordlist.

Metasploit Framework 6.5.6 is pinned to upstream Git commit `c6e99d08265b081d2f180086790b12811642c278`, not a Debian package. TraceOS opens its console in a terminal without selecting a target, module, or exploit. SQLmap opens interactively; the user reviews its prompts. Metasploit itself does not enforce a target scope, so only use its console within an authorized assessment.

## Image OSINT

Image OSINT runs locally: it computes SHA-256, identifies MIME type and image dimensions, extracts metadata with ExifTool, and attempts local OCR with Tesseract. The GUI does not upload selected images. Google Lens, Bing Visual Search, and TinEye are optional browser handoffs; TraceOS displays an external-service warning and the user must choose and submit the image on that site.

The OSINT workbench includes Sherlock Project 0.16.2, Maigret 0.6.6, h8mail 2.5.6, Holehe 1.61, PhoneInfoga 2.11.0, Blackbird pinned to upstream commit `b45505080ef51bb3ef52dc29879ee6bef31e5b94`, GHunt 2.3.4, theHarvester 4.11.1, DNSRecon 1.6.3, and dnstwist 20250130. Blackbird uses an authoritative runtime dependency lock kept in `config/third-party/blackbird-requirements.txt`; its optional AI path is not enabled by TraceOS. Advanced OSINT tools are pinned to upstream releases and validated as packaged command surfaces during ISO builds.

## Block 6A: Offensive Operations Foundation

Block 6A adds a real offensive-assessment foundation rather than mock buttons:

- **Metasploit Framework 6.5.6**, pinned to upstream Git commit `c6e99d08265b081d2f180086790b12811642c278`, with `msfconsole`, `msfvenom`, and `msfdb`.
- **enum4linux-ng 1.3.10**, pinned to upstream commit `f34e7bb`, for structured Windows/Samba enumeration.
- The build validates installation and command surfaces but does not execute offensive actions against targets during ISO construction.

## Block 6B: Windows / Active Directory / Authentication Assessment

Block 6B extends the offensive workstation into enterprise identity and authentication assessment:

- **BloodHound.py 1.9.0**, pinned to upstream Git commit `fd3f322e066d66314bfb31d4ae6f497df5872177`, for BloodHound-compatible Active Directory collection.
- **Kerbrute 1.0.3**, pinned to upstream Git commit `9dad6e171abdc7491f587c793aa05411264a3393` and built from source with Debian's Go toolchain.
- **Hashcat 6.2.6+ds2-1** and **John the Ripper 1.9.0-2**, using Debian Trixie packages for offline password/hash recovery assessment.
- Existing **Impacket 0.13.1**, **NetExec 1.5.1**, **Certipy 5.1.0**, LDAP, SMB, RPC, and Kerberos tooling form the surrounding AD assessment stack.
- The tools are operator-invoked and intended for explicitly authorized assessments; TraceOS does not automate uncontrolled credential spraying or destructive actions during ISO construction.
- The full BloodHound CE server/frontend remains a separate evaluation item because its current upstream release is not shipped as a simple standalone Linux asset. BloodHound.py is the portable collector component bundled in this block.

## Block 6C: Red team depth

Block 6C adds the tools working red teams actually reach for after NetExec and BloodHound. Several are well known inside that community and rarely packaged in a general enterprise image:

- **Sliver 1.7.8** client and server, the current open-source command-and-control pair. The build runs `version` only. It does not generate an implant or start a listener.
- **AzureHound 3.1.3**, for Microsoft Entra and Azure collection into BloodHound.
- **lsassy 3.1.16**, for remote credential-material assessment over an authorized admin channel.
- **Adalanche r1014**, an Active Directory ACL and attack-path explorer that is not BloodHound.
- **ldeep 2.0.3**, for LDAP enumeration that the usual collectors skip.
- **Pretender 1.4.1** and **mitm6 0.3.0**, for name-resolution and IPv6 DNS takeover assessment.
- **Ligolo-ng 0.9.2** proxy and agent, for an operator-started tunnel. The image does not launch either one during the build.
- **bloodyAD 2.5.5**, **Coercer 2.4.3**, **pre2k 3.0**, and **SCCMHunter 2.0.0**, for AD object assessment, authentication coercion, legacy computer accounts, and SCCM hierarchy identification.

Every binary is pinned to a release checksum or a Git commit. The build checks the command surface only. It does not coerce authentication, poison name resolution, open a tunnel, or send traffic to a target. The Control Centre opens each tool at its help or version screen inside a terminal, and the existing authorization checkbox still applies.

## Credentials, defence depth and cloud OSINT

These sit in the Control Centre as their own actions, not as a pile of unmarked commands:

- **Credentials** page: TruffleHog 3.99.3 scans a local folder with verification disabled. NoseyParker 0.24.0 scans that folder into `/var/tmp/traceos-noseyparker`, and Report reads the datastore. pypykatz 0.6.13 reads a minidump you select. DonPAPI 2.1.0, pinned to commit `4f01e2b893d3dfbc327b68797943cc2f00c5dd94`, opens a console only. PyPI 2.0.1 is not used because it forces lxml 4.9.3, which does not build on Python 3.13.
- **Defence** page: Chainsaw 2.17.1 hunts a local log folder with Sigma Windows rules pinned to commit `05d1031f537e830b76da53bae2400c5814c89165`. capa 10.0.0 reports what one binary can do. osquery 5.24.0 runs one process query and does not start `osqueryd`. Velociraptor 0.77.3 runs one local identity query and does not start a server.
- **Image OSINT** has a Read Metadata button for ExifTool. **Investigation Centre** has Cloud Enum for one public cloud keyword.

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
- Image forensics integration
- Expanded image-forensics workflows
- OSINT workspace
- Core OSINT tools bundled in the live image
- Additional people and domain OSINT providers
- Advanced OSINT and entity-intelligence collection
- Red Team assessment expansion
- Blue Team detection and hunting expansion
- Purple Team ATT&CK-linked validation workflows
- Local Ari/llama.cpp integration
- Installer and signed releases
