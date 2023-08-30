package main

import (
	"log"
	"os"

	"securityscanner/pkg/policy"
	"securityscanner/pkg/scanner"
)

func main() {
	log.Println("Application is starting...")

	imagesToScan := os.Args[1:]

	if len(imagesToScan) == 0 {
		log.Println("No Docker image names provided. Exiting...")
		return
	}

	policyEnforcer := policy.NewEnforcer(
		[]policy.Policy{
				&policy.AnyLabelExistsPolicy{},
				})

	for _, image := range imagesToScan {
		dockerImage, err := scanner.ScanImage(image)
		if err != nil {
			log.Printf("Error while scanning image %s: %v\n", image, err)
			continue
		}

		policyStatuses := policyEnforcer.Check(dockerImage)
		violationsExist := false
		for _, status := range policyStatuses {
			if status.IsViolation {
				violationsExist = true
				log.Printf("Image %s violates policy: %s\n", dockerImage.Name, status.Message)
			}
		}

		if !violationsExist {
			log.Printf("Image %s adheres to all policies.\n", dockerImage.Name)
		} else if len(dockerImage.Vulnerabilities) > 0 {
			log.Printf("Vulnerabilities were detected for image %s.\n", dockerImage.Name)
		}
	}

	log.Println("Application has finished.")
}