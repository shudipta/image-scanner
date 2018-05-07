package v1alpha1

import (
	"github.com/appscode/go/log"
	"github.com/soter/scanner/pkg/types"
)

func (r ScanResult) HasVulnerabilities(maxAccepted types.Severity) bool {
	for _, feature := range r.Features {
		for _, vul := range feature.Vulnerabilities {
			reported, err := types.ParseSeverity(vul.Severity)
			if err != nil {
				log.Warningf("failed to parse severity level %s of feature %s:%s", vul.Severity, feature.Name, feature.Version)
				reported = types.SeverityUnknown
			}
			if reported < maxAccepted {
				return true
			}
		}
	}
	return false
}

func (r WorkloadReviewResponse) HasVulnerabilities(maxAccepted types.Severity) bool {
	for _, img := range r.Images {
		if img.HasVulnerabilities(maxAccepted) {
			return true
		}
	}
	return false
}
