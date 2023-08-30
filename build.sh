#!/bin/sh

if ! command -v trivy &> /dev/null
then
    echo 'Trivy is not installed. Installing it now...'
    curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
    echo deb https://aquasecurity.github.io/trivy-repo/deb buster main | sudo tee -a /etc/apt/sources.list.d/trivy.list
    sudo apt-get update
    sudo apt-get install trivy
fi

echo 'Building the Security Scanner application...'
go build -o securityscanner ./cmd/main/main.go

if [ $? -ne 0 ]; then
  echo 'Build failed. Exiting script.'
  exit 1
fi

echo 'Build successful. Running application...'

./securityscanner "$@"

if [ $? -ne 0 ]; then
  echo 'Application failed to run.'
  exit 1
else
  echo 'Application ran successfully.'
fi