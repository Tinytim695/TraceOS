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

- **Amnesic (wipe session)**: boots with `nopersistence`. Session changes are kept in the live overlay and are not written to a persistence volume.
- **Persistent**: boots with `persistence` and looks for a live-boot persistence volume.
- **Persistent (Encrypted LUKS)**: boots with `persistence persistence-encryption=luks` and permits LUKS persistence.
- **Persistent from USB** and **Encrypted Persistent from USB** are available under advanced boot options.

For persistence, live-boot expects a persistence volume labelled `persistence` (or another explicitly selected label) with a `persistence.conf` file. The volume can be prepared separately on an ext4 filesystem or another supported medium. TraceOS does not automatically partition, format, encrypt, or select a user's disks.

The default boot entry is Amnesic, deliberately making the safest session behaviour the automatic path. The Control Centre reports the active session mode.

A separate recovery/factory-reset workflow will be developed for installed systems. It will require explicit confirmation and will distinguish ordinary reset from hardware/device secure-erase operations.

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
