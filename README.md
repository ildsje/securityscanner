# README.md 

## securityscanner

`securityscanner` is a Golang-based project built to analyze vulnerabilities in Docker images utilizing [Trivy](https://github.com/aquasecurity/trivy), a Simple and Comprehensive Vulnerability Scanner for Containers and other Artifacts.

### Prerequisites

- [Go](https://golang.org/doc/install) v1.21 or later
- [Docker](https://docs.docker.com/get-docker/)

### Setup and Installation

1. To start using `securityscanner`, you need to clone the project to your local machine.

```bash
git clone https://github.com/ildjse/securityscanner.git
```
2. Change your directory to securityscanner:

```bash
cd securityscanner
```
3. Build the project with:

```bash
go build -o securityscanner
```

### Usage

Run a docker image scan using Trivy:

```bash
./securityscanner <Docker-Image-Name:Version>
```
For instance, if you're scanning a Docker image named nginx, you would run:

```bash
./securityscanner ubuntu:latest
```
