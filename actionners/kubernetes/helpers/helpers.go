package helpers

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
	appsv1 "k8s.io/api/apps/v1"
)

const ValidatorMinHealthyReplicas = "is_absolut_or_percent"

func ValidateMinHealthyReplicas(fl validator.FieldLevel) bool {
	minHealthyReplicas := fl.Field().String()
	reg := regexp.MustCompile(`\d+(%)?`)
	if !reg.MatchString(minHealthyReplicas) {
		return false
	}
	if strings.HasSuffix(minHealthyReplicas, "%") {
		percent, err := strconv.ParseInt(strings.TrimSuffix(minHealthyReplicas, "%"), 10, 64)
		if err != nil {
			return false
		}
		if percent < 0 || percent > 100 {
			return false
		}
	} else {
		absolut, err := strconv.ParseInt(minHealthyReplicas, 10, 64)
		if err != nil {
			return false
		}
		if absolut < 0 {
			return false
		}
	}
	return true
}

// ParseMinHealthyReplicas returns an integer for the value and a string for the type ("percent" or "absolut")
func ParseMinHealthyReplicas(value string) (int64, string, error) {
	if strings.HasSuffix(value, "%") {
		percent, err := strconv.ParseInt(strings.TrimSuffix(value, "%"), 10, 64)
		if err != nil {
			return 0, "", err
		}
		return percent, "percent", nil
	}
	absolut, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, "", err
	}
	return absolut, "absolut", nil
}

// HasEnoughHealthyReplicas reports whether the ReplicaSet currently has enough
// ready replicas to satisfy the min_healthy_replicas requirement described by
// minValue and kind (as returned by ParseMinHealthyReplicas).
//
// For an absolute requirement, the ready replica count is compared directly to
// minValue. For a percentage, the threshold is computed against the desired
// replica count (rs.Spec.Replicas), not the current ready count, and rounded up
// (ceil) so availability is protected conservatively.
func HasEnoughHealthyReplicas(rs *appsv1.ReplicaSet, minValue int64, kind string) (bool, error) {
	if rs == nil {
		return false, fmt.Errorf("no replicaset found")
	}

	readyReplicas := int64(rs.Status.ReadyReplicas)

	switch kind {
	case "absolut":
		return readyReplicas >= minValue, nil
	case "percent":
		var desiredReplicas int64
		if rs.Spec.Replicas != nil {
			desiredReplicas = int64(*rs.Spec.Replicas)
		}
		threshold := int64(math.Ceil(float64(minValue) / 100.0 * float64(desiredReplicas)))
		return readyReplicas >= threshold, nil
	default:
		return false, fmt.Errorf("unknown min_healthy_replicas kind %q", kind)
	}
}
