---
title: Installing Teleport
description: The guide for installing Teleport on servers and into Kubernetes clusters
---

# Installation

Teleport core service [`teleport`](cli-docs.md#teleport) and admin tool [`tctl`](cli-docs.md#tctl) have been designed to run on **Linux** and **Mac** operating systems. The Teleport user client [`tsh`](cli-docs.md#tsh) and UI are available for **Linux, Mac** and **Windows** operating systems.

## Linux

The following examples install the 64-bit version of Teleport binaries, but
32-bit (i386) and ARM binaries are also available. Check the [Latest
Release](https://gravitational.com/teleport/download/) page for the most
up-to-date information.

=== "Debian/Ubuntu (DEB)"

    ```bash
    # Install our public key.
    $ curl https://deb.releases.teleport.dev/teleport-pubkey.asc | sudo apt-key add -
    # Add repo to APT
    $ add-apt-repository 'deb https://deb.releases.teleport.dev/ stable main'
    # Update APT Cache
    $ apt-get
    # Install Teleport
    $ apt install teleport
    ```

=== "Amazon Linux 2/RHEL/Fedora (RPM)"

    ```bash
    $ yum-config-manager --add-repo https://rpm.releases.teleport.dev/teleport.repo
    $ yum install teleport
    ```

=== "ARMv7 (32-bit)"

    ```bash
    $ curl https://get.gravitational.com/teleport-v{{ teleport.version }}-linux-arm-bin.tar.gz.sha256
    # <checksum> <filename>
    $ curl -O https://get.gravitational.com/teleport-v{{ teleport.version }}-linux-arm-bin.tar.gz
    $ shasum -a 256 teleport-v{{ teleport.version }}-linux-arm-bin.tar.gz
    # Verify that the checksums match
    $ tar -xzf teleport-v{{ teleport.version }}-linux-arm-bin.tar.gz
    $ cd teleport
    $ ./install
    ```

=== "ARM64/ARMv8 (64-bit)"

    ```bash
    $ curl https://get.gravitational.com/teleport-v{{ teleport.version }}-linux-arm64-bin.tar.gz.sha256
    # <checksum> <filename>
    $ curl -O https://get.gravitational.com/teleport-v{{ teleport.version }}-linux-arm64-bin.tar.gz
    $ shasum -a 256 teleport-v{{ teleport.version }}-linux-arm64-bin.tar.gz
    # Verify that the checksums match
    $ tar -xzf teleport-v{{ teleport.version }}-linux-arm64-bin.tar.gz
    $ cd teleport
    $ ./install
    ```

=== "Tarball"

    ```bash
    $ curl https://get.gravitational.com/teleport-v{{ teleport.version }}-linux-amd64-bin.tar.gz.sha256
    # <checksum> <filename>
    $ curl -O https://get.gravitational.com/teleport-v{{ teleport.version }}-linux-amd64-bin.tar.gz
    $ shasum -a 256 teleport-v{{ teleport.version }}-linux-amd64-bin.tar.gz
    # Verify that the checksums match
    $ tar -xzf teleport-v{{ teleport.version }}-linux-amd64-bin.tar.gz
    $ cd teleport
    $ ./install
    ```

## Docker

Please follow our [Getting started with Teleport using Docker](quickstart-docker.md) or with [Teleport Enterprise using Docker](enterprise/quickstart-enterprise.md#run-teleport-enterprise-using-docker) for install and setup instructions.

```bash
$ docker pull quay.io/gravitational/teleport:{{ teleport.version }}
```

## Helm
Please follow our [Helm Chart Readme](https://github.com/gravitational/teleport/tree/master/examples/chart/teleport) for install and setup instructions.

```bash
$ helm repo add teleport https://charts.releases.teleport.dev
$ helm install teleport teleport/teleport
```

## MacOS

=== "Download"

    [Download MacOS .pkg installer](https://goteleport.com/teleport/download?os=macos) (tsh client only, signed) file, double-click to run the Installer.

    !!! note

        This method only installs the `tsh` client for interacting with Teleport clusters.
        If you need the `teleport` server or `tctl` admin tool, use the "Terminal" method instead.

=== "Homebrew"

    ```bash
    $ brew install teleport
    ```

    !!! note

        The Teleport package in Homebrew is not maintained by Teleport. We recommend the use of our [own Teleport packages](https://goteleport.com/teleport/download?os=macos).

=== "Terminal"

    ```bash
    $ curl -O https://get.gravitational.com/teleport-{{ teleport.version }}.pkg
    $ sudo installer -pkg teleport-{{ teleport.version }}.pkg -target / # Installs on Macintosh HD
    Password:
    installer: Package name is teleport-{{ teleport.version }}
    installer: Upgrading at base path /
    installer: The upgrade was successful.
    $ which teleport
    /usr/local/bin/teleport
    ```


## Windows (tsh client only)

As of version v3.0.1 we have `tsh` client binary available for Windows 64-bit
architecture - `teleport` and `tctl` are not supported.

=== "Powershell"

    ```bash
    > curl https://get.gravitational.com/teleport-v{{ teleport.version }}-windows-amd64-bin.zip.sha256
    # <checksum> <filename>
    > curl -O teleport-v{{ teleport.version }}-windows-amd64-bin.zip https://get.gravitational.com/teleport-v{{ teleport.version }}-windows-amd64-bin.zip
    > echo %PATH% # Edit %PATH% if necessary
    > certUtil -hashfile teleport-v{{ teleport.version }}-windows-amd64-bin.zip SHA256
    SHA256 hash of teleport-v{{ teleport.version }}-windows-amd64-bin.zip:
    # <checksum> <filename>
    CertUtil: -hashfile command completed successfully.
    # Verify that the checksums match
    # Move `tsh` to your %PATH%
    ```

## Installing from Source

Gravitational Teleport is written in Go language. It requires **Golang v{{ teleport.golang }}**
or newer. Check [the repo
README](https://github.com/gravitational/teleport#building-teleport) for the
latest requirements.

### Install Go

If you don't already have Golang installed you can [see installation
instructions here](https://golang.org/doc/install). If you are new to Go there
are a few quick set up things to note:

- Go installs all dependencies _for all projects_ in a single directory
  determined by the `$GOPATH` variable. The default directory is
  `GOPATH=$HOME/go` but you can set it to any directory you wish.
- If you plan to use Golang for more than just this installation you may want to
  `echo "export GOPATH=$HOME/go" >> ~/.bashrc` (or your shell config).

### Build Teleport

```bash
# get the source & build:
$ mkdir -p $GOPATH/src/github.com/gravitational
$ cd $GOPATH/src/github.com/gravitational
$ git clone https://github.com/gravitational/teleport.git
$ cd teleport
# Make sure you have `zip` installed - the Makefile uses it
$ make full
# create the default data directory before running `teleport`
$ sudo mkdir -p /var/lib/teleport
$ sudo chown $USER /var/lib/teleport
```

If the build succeeds, the binaries `teleport, tsh`, and `tctl` are now in the
directory `$GOPATH/src/github.com/gravitational/teleport/build`

<!-- Notes on what to do if the build does not succeed, troubleshooting -->


## Checksums

Gravitational Teleport provides a checksum from the [Downloads](https://gravitational.com/teleport/download/).
This should be used to verify the integrity of our binary.

![Teleport Checksum](../img/teleport-sha.png)

If you download Teleport via an automated system, you can programmatically
obtain the checksum  by adding `.sha256` to the binary. This is the method shown
in the installation examples.

```bash
$ export version=v{{ teleport.version }}
$ export os=linux # 'darwin' 'linux' or 'windows'
$ export arch=amd64 # '386' 'arm' on linux or 'amd64' for all distros
$ curl https://get.gravitational.com/teleport-$version-$os-$arch-bin.tar.gz.sha256
# <checksum> <filename>
```
