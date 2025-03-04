# Container Security Scan Action

This GitHub Action builds a Docker image and performs a security scan using [Trivy](https://github.com/aquasecurity/trivy). It is designed to help you automate the process of scanning Docker images for vulnerabilities and manage the results efficiently.

## Description

The action checks out your repository, builds a Docker image using the specified Dockerfile, and runs a security scan on the image. The results of the scan are saved as an artifact for further inspection.

## Inputs

| Name         | Description                          | Required | Default   |
|--------------|--------------------------------------|----------|-----------|
| `registry`   | Docker registry to use               | No       | `ghcr.io` |
| `dockerfile` | Path to the Dockerfile               | No       | `Dockerfile` |
| `image_name` | Name of the Docker image             | Yes      |           |

## Outputs

This action does not produce any direct outputs, but it uploads the scan report as an artifact.

## Usage

Here's an example of how to use this action in a workflow:

```yaml
name: Container Security Scan Workflow

on:
  push:
    branches: [dev, staging]
    tags: ['v*.*.*']

jobs:
  container-scan:
    runs-on: th878
    environment: ${{ github.head_ref || github.ref_name }}
    permissions:
      contents: read
      packages: write
      id-token: write

    steps:
      - name: Run Container Security Scan Action
        uses: ./  # Assumes the action.yml is at the root of the repository
        with:
          image_name: data-accuracy-tool-dat-api-security-${{ github.head_ref || github.ref_name }}
