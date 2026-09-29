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

## Roadmap

- Desktop foundation
- TraceOS control centre
- CaseForge integration
- ShellSieve integration
- TraceLock integration
- DNAProcess integration
- Image forensics integration
- OSINT workspace
- Local Ari/llama.cpp integration
- Installer and signed releases
