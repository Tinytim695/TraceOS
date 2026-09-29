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

The first milestone establishes a bootable Debian 13 "trixie" XFCE desktop image with a TraceOS launcher, core system utilities, networking tools, forensic/image packages, and reproducible GitHub Actions builds.

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

TraceOS disables desktop auto-mount/auto-open behaviour at session start and disables Thunar thumbnails by default. The Thunar volume-management auto-mount helper is not installed. This reduces the chance of accidentally changing evidence media, but TraceOS is not a substitute for a hardware write blocker.

## Updates

TraceOS includes Debian's `package-update-indicator`, intended for Xfce desktops, so normal Debian updates can be reported to the user. Use `traceos update check` to refresh package metadata and inspect available upgrades, or `traceos update` for a user-approved Debian full upgrade. Bundled third-party OSINT tools stay pinned until a tested TraceOS update replaces them.

## OSINT workbench

The initial OSINT set is now Sherlock Project 0.16.2, Maigret 0.6.6, h8mail 2.5.6, and Blackbird pinned to upstream commit `b45505080ef51bb3ef52dc29879ee6bef31e5b94`. Holehe and socialscan were removed from the image because their maintenance level did not justify making them part of the core set. Blackbird is installed from source with its upstream requirements locked by version, and its optional AI path is not enabled by TraceOS.

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
- OSINT workspace
- Core OSINT tools bundled in the live image
- Local Ari/llama.cpp integration
- Installer and signed releases
