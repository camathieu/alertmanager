// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0

package relabel

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/prometheus/common/model"
)

// Action is the relabeling action to apply to an alert label set.
type Action string

const (
	Replace   Action = "replace"
	Keep      Action = "keep"
	Drop      Action = "drop"
	LabelDrop Action = "labeldrop"
	LabelKeep Action = "labelkeep"
	Lowercase Action = "lowercase"
	Uppercase Action = "uppercase"
)

// UnmarshalYAML implements yaml.Unmarshaler.
func (a *Action) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	action := Action(strings.ToLower(s))
	switch action {
	case Replace, Keep, Drop, LabelDrop, LabelKeep, Lowercase, Uppercase:
		*a = action
		return nil
	default:
		return fmt.Errorf("unknown relabel action %q", s)
	}
}

// Regexp is a YAML-friendly regular expression that keeps its original text.
type Regexp struct {
	*regexp.Regexp
	original string
}

// MustNewRegexp returns a new Regexp or panics if expression is invalid.
func MustNewRegexp(expr string) Regexp {
	re, err := NewRegexp(expr)
	if err != nil {
		panic(err)
	}
	return re
}

// NewRegexp returns a new Regexp. Expressions are anchored to match the whole
// input, matching Prometheus relabeling behavior.
func NewRegexp(expr string) (Regexp, error) {
	re, err := regexp.Compile("^(?s:" + expr + ")$")
	if err != nil {
		return Regexp{}, err
	}
	return Regexp{Regexp: re, original: expr}, nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (r *Regexp) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	re, err := NewRegexp(s)
	if err != nil {
		return err
	}
	*r = re
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (r Regexp) MarshalYAML() (any, error) {
	return r.String(), nil
}

// MarshalJSON implements json.Marshaler.
func (r Regexp) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

// String returns the original expression.
func (r Regexp) String() string {
	return r.original
}

// IsZero implements yaml.IsZeroer.
func (r Regexp) IsZero() bool {
	return r.Regexp == nil
}

// Config is a relabel rule applied to incoming alert labels.
type Config struct {
	SourceLabels model.LabelNames `yaml:"source_labels,flow,omitempty" json:"source_labels,omitempty"`
	Separator    string           `yaml:"separator,omitempty" json:"separator,omitempty"`
	Regex        Regexp           `yaml:"regex,omitempty" json:"regex,omitempty"`
	TargetLabel  string           `yaml:"target_label,omitempty" json:"target_label,omitempty"`
	Replacement  string           `yaml:"replacement,omitempty" json:"replacement,omitempty"`
	Action       Action           `yaml:"action,omitempty" json:"action,omitempty"`
}

var defaultConfig = Config{
	Action:      Replace,
	Separator:   ";",
	Regex:       MustNewRegexp("(.*)"),
	Replacement: "$1",
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (c *Config) UnmarshalYAML(unmarshal func(any) error) error {
	*c = defaultConfig
	type plain Config
	return unmarshal((*plain)(c))
}

// Validate checks that this relabel rule can be applied safely.
func (c *Config) Validate() error {
	if c.Action == "" {
		return errors.New("relabel action cannot be empty")
	}
	if c.Regex.Regexp == nil {
		return errors.New("relabel regex cannot be empty")
	}

	switch c.Action {
	case Replace, Lowercase, Uppercase:
		if c.TargetLabel == "" {
			return fmt.Errorf("relabel configuration for %s action requires 'target_label' value", c.Action)
		}
		if !model.UTF8Validation.IsValidLabelName(c.TargetLabel) {
			return fmt.Errorf("%q is invalid 'target_label' for %s action", c.TargetLabel, c.Action)
		}
	case Keep, Drop, LabelDrop, LabelKeep:
	default:
		return fmt.Errorf("unknown relabel action %q", c.Action)
	}

	for _, label := range c.SourceLabels {
		if !model.UTF8Validation.IsValidLabelName(string(label)) {
			return fmt.Errorf("%q is invalid 'source_labels' value", label)
		}
	}

	return nil
}

// Process applies relabel configs to labels. The returned bool is false when
// relabeling dropped the alert.
func Process(labels model.LabelSet, cfgs ...*Config) (model.LabelSet, bool) {
	if len(cfgs) == 0 {
		return labels, true
	}

	res := make(model.LabelSet, len(labels))
	for k, v := range labels {
		res[k] = v
	}

	for _, cfg := range cfgs {
		if cfg == nil {
			continue
		}
		if !process(res, cfg) {
			return nil, false
		}
	}

	return res, true
}

func process(labels model.LabelSet, cfg *Config) bool {
	value := sourceValue(labels, cfg.SourceLabels, cfg.Separator)

	switch cfg.Action {
	case Drop:
		return !cfg.Regex.MatchString(value)
	case Keep:
		return cfg.Regex.MatchString(value)
	case Replace:
		indexes := cfg.Regex.FindStringSubmatchIndex(value)
		if indexes == nil {
			return true
		}
		replacement := string(cfg.Regex.ExpandString(nil, cfg.Replacement, value, indexes))
		target := model.LabelName(cfg.TargetLabel)
		if replacement == "" {
			delete(labels, target)
		} else {
			labels[target] = model.LabelValue(replacement)
		}
	case LabelDrop:
		for name := range labels {
			if cfg.Regex.MatchString(string(name)) {
				delete(labels, name)
			}
		}
	case LabelKeep:
		for name := range labels {
			if !cfg.Regex.MatchString(string(name)) {
				delete(labels, name)
			}
		}
	case Lowercase:
		labels[model.LabelName(cfg.TargetLabel)] = model.LabelValue(strings.ToLower(value))
	case Uppercase:
		labels[model.LabelName(cfg.TargetLabel)] = model.LabelValue(strings.ToUpper(value))
	}

	return true
}

func sourceValue(labels model.LabelSet, names model.LabelNames, separator string) string {
	values := make([]string, 0, len(names))
	for _, name := range names {
		values = append(values, string(labels[name]))
	}
	return strings.Join(values, separator)
}
