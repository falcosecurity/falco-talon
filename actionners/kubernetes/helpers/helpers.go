package helpers

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
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
