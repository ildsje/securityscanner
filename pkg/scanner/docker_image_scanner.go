package scanner

import (
	"os/exec"
	"encoding/json"
	"strings"
	"fmt"
)

type TrivyOutput struct {
	SchemaVersion  int                    `json:"SchemaVersion"`
	ArtifactName   string                 `json:"ArtifactName"`
	ArtifactType   string                 `json:"ArtifactType"`
	Metadata       TrivyMetadata          `json:"Metadata"`
	Results        []TrivyVulnerabilities `json:"Results"`
}

type TrivyMetadata struct {
	OS           TrivyOS                 `json:"OS"`
	ImageID      string                  `json:"ImageID"`
	DiffIDs      []string                `json:"DiffIDs"`
	RepoTags     []string                `json:"RepoTags"`
	RepoDigests  []string                `json:"RepoDigests"`
	ImageConfig  map[string]interface{}  `json:"ImageConfig"`
}

type TrivyOS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

type TrivyVulnerabilities struct {
	Target          string        `json:"Target"`
	Class           string        `json:"Class"`
	Type            string        `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgID           string `json:"PkgID"`
	PkgName         string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	Status string `json:"Status"`
	Layer TrivyLayer `json:"Layer"`
	SeveritySource string `json:"SeveritySource"`
	PrimaryURL string `json:"PrimaryURL"`
	DataSource interface{} `json:"DataSource"`
	Title string `json:"Title"`
	Description string `json:"Description"`
}

type TrivyLayer struct {
	DiffID string `json:"DiffID"`    
}

type DockerImage struct {
	Name            string 
	Tag             string
	Vulnerabilities []Vulnerability
	Labels          map[string]string
}

func ScanImage(image string) (DockerImage, error) {
	i := strings.LastIndex(image, ":")
	name := image[:i]
	tag := image[i+1:]

	cmd := exec.Command("trivy", "image", "--format", "json", image)
	output, err := cmd.Output()

	if err != nil {
		return DockerImage{}, err
	}

	var trivyOutput TrivyOutput
	err = json.Unmarshal(output, &trivyOutput)

	if err != nil {
		return DockerImage{}, err
	}

	for _, result := range trivyOutput.Results {
		for _, vulnerability := range result.Vulnerabilities {
			fmt.Println(vulnerability.VulnerabilityID)
			fmt.Println(vulnerability.PkgName)
		}
	}

	return DockerImage{
		Name: name,
		Tag:  tag,
		Vulnerabilities: trivyOutput.Results[0].Vulnerabilities,
		Labels: make(map[string]string),
		}, nil
}