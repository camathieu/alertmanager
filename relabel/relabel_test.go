// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0

package relabel

import (
	"testing"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestProcessRewritesEnvironmentSpecificSeverity(t *testing.T) {
	var cfgs []*Config
	require.NoError(t, yaml.UnmarshalStrict([]byte(`
- source_labels: [environment, severity_prod]
  separator: ;
  regex: prod;(.+)
  target_label: severity
  replacement: $1
  action: replace
- source_labels: [environment, severity_preprod]
  separator: ;
  regex: preprod;(.+)
  target_label: severity
  replacement: $1
  action: replace
- regex: severity_(prod|preprod)
  action: labeldrop
`), &cfgs))

	for _, cfg := range cfgs {
		require.NoError(t, cfg.Validate())
	}

	for _, tc := range []struct {
		environment string
		severity    model.LabelValue
	}{
		{environment: "prod", severity: "page"},
		{environment: "preprod", severity: "notification"},
	} {
		t.Run(tc.environment, func(t *testing.T) {
			got, keep := Process(model.LabelSet{
				"alertname":        "DiskFull",
				"environment":      model.LabelValue(tc.environment),
				"severity_prod":    "page",
				"severity_preprod": "notification",
			}, cfgs...)

			require.True(t, keep)
			require.Equal(t, tc.severity, got["severity"])
			require.NotContains(t, got, model.LabelName("severity_prod"))
			require.NotContains(t, got, model.LabelName("severity_preprod"))
		})
	}
}

func TestProcessDropsAlerts(t *testing.T) {
	cfg := &Config{
		Action:       Drop,
		SourceLabels: model.LabelNames{"environment"},
		Separator:    ";",
		Regex:        MustNewRegexp("dev"),
		Replacement:  "$1",
	}
	require.NoError(t, cfg.Validate())

	got, keep := Process(model.LabelSet{"environment": "dev"}, cfg)

	require.False(t, keep)
	require.Nil(t, got)
}

func TestConfigValidationRequiresTargetLabelForReplace(t *testing.T) {
	cfg := &Config{
		Action:      Replace,
		Separator:   ";",
		Regex:       MustNewRegexp("(.*)"),
		Replacement: "$1",
	}

	require.EqualError(t, cfg.Validate(), "relabel configuration for replace action requires 'target_label' value")
}
