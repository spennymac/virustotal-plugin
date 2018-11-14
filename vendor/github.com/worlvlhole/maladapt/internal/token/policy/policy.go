package policy

import (
	"encoding/json"
	"errors"
	"strings"
)

// RuleType represents a restriction type
type RuleType string

const (
	//RateLimitRuleType rule for a policy
	RateLimitRuleType RuleType = "rate_limit"
	//PermissionRuleType rule for a policy
	PermissionRuleType RuleType = "permission"
)

// RuleValidation function that validates the rule
type RuleValidation func(*Rule) error

var (
	//ErrFailedToValidate returned when a policy rule is not valid
	ErrFailedToValidate = errors.New("failed to validate")
	//ValidationChecks is a map holding rule validation functions for each rule type
	ValidationChecks = map[RuleType]RuleValidation{
		RateLimitRuleType:  validateRateLimit,
		PermissionRuleType: normalizeAndValidatePermission,
	}
)

var (
	//ErrInvalidRule error describing a invalid rule
	ErrInvalidRule = errors.New("invalid rule")

	validRules = map[RuleType]struct{}{
		RateLimitRuleType:  {},
		PermissionRuleType: {},
	}
)

// Policy describes what a token is allowed to do
type Policy struct {
	Rules []Rule
}

// Rule describes a specific policy rule
type Rule struct {
	Type          RuleType               `json:"type"`
	Configuration map[string]interface{} `json:"configuration"`
}

//UnmarshalJSON parses JSON encoded string and normalizes it by performing strings.ToLower
func (rt *RuleType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	*rt = RuleType(strings.ToLower(s))

	return nil
}

//IsValidRuleType returns whether a rule is valid
func IsValidRuleType(rt RuleType) bool {
	_, ok := validRules[rt]
	return ok
}

func validateRateLimit(r *Rule) error {
	if r.Type != RateLimitRuleType {
		return ErrFailedToValidate
	}

	if r.Configuration == nil || len(r.Configuration) == 0 {
		return ErrFailedToValidate
	}

	x, ok := r.Configuration["hits_per_minute"]
	if !ok {
		return ErrFailedToValidate
	}

	_, ok = x.(float64)
	if !ok {
		return ErrFailedToValidate
	}

	return nil
}
