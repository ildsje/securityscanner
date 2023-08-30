package policy

import (
	"fmt"
	"strings"
	"securityscanner/pkg/scanner"
)

type Enforcer interface {
	Check(image scanner.DockerImage) []PolicyStatus
}

type SimpleEnforcer struct {
	policies []Policy  
}

type PolicyStatus struct {
	IsViolation bool 
	Message     string 
}

type Policy interface {
	Check(image scanner.DockerImage) PolicyStatus
}

func NewEnforcer(policies []Policy) Enforcer {
	return &SimpleEnforcer{policies: policies}
}

func (e *SimpleEnforcer) Check(image scanner.DockerImage) []PolicyStatus {
	var statuses []PolicyStatus

	for _, policy := range e.policies {
		statuses = append(statuses, policy.Check(image))
	}

	return statuses
}

type TrustedRegistryPolicy struct {
	TrustedRegistry string
}

func (p *TrustedRegistryPolicy) Check(image scanner.DockerImage) PolicyStatus {
	if !strings.Contains(image.Name, p.TrustedRegistry) {  // обновлено
		return PolicyStatus {IsViolation: true, Message: fmt.Sprintf("Image is not from the TrustedRegistry: %s", p.TrustedRegistry)}
	}
	return PolicyStatus {IsViolation: false, Message: "Image is from the TrustedRegistry."}
}

type AnyLabelExistsPolicy struct{}

func (p *AnyLabelExistsPolicy) Check(image scanner.DockerImage) PolicyStatus {
	if len(image.Labels) == 0 {
		return PolicyStatus{IsViolation: true, Message: "Image does not contain any labels"}
	}
	return PolicyStatus{IsViolation: false, Message: "Image contains labels"}
}

func initEnforcer() Enforcer {
	return NewEnforcer([]Policy{
		&TrustedRegistryPolicy{
			TrustedRegistry: "library",
		},
		&AnyLabelExistsPolicy{},
		})
}