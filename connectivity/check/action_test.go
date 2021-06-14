// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package check

import (
	"context"
	"testing"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

func TestAction_matchAllFlowRequirements(t *testing.T) {
	ct, err := NewConnectivityTest(nil, Parameters{FlowValidation: FlowValidationModeStrict})
	assert.NoError(t, err)
	a := Action{
		src:  &Pod{Pod: &v1.Pod{Status: v1.PodStatus{PodIP: "1.2.3.4"}}, port: 45678},
		dst:  &Pod{Pod: &v1.Pod{Status: v1.PodStatus{PodIP: "5.6.7.8"}}, port: 8000},
		test: ct.NewTest("dummy-test"),
	}
	res := a.matchAllFlowRequirements(context.Background(), nil, "my-pod", nil)
	assert.False(t, res.NeedMoreFlows)
	assert.Equal(t, -1, res.FirstMatch)
	assert.Equal(t, -1, res.LastMatch)

	egressFlowRequirements := a.GetEgressRequirements(FlowParameters{})
	res = a.matchAllFlowRequirements(context.Background(), nil, "my-pod", egressFlowRequirements)
	assert.True(t, res.NeedMoreFlows)
	assert.Equal(t, -1, res.FirstMatch)
	assert.Equal(t, -1, res.LastMatch)

	flows := []*observer.GetFlowsResponse{
		{
			ResponseTypes: &observer.GetFlowsResponse_Flow{
				Flow: &flow.Flow{
					IP: &flow.IP{
						Source:      a.src.Address(),
						Destination: a.dst.Address(),
					},
					L4: &flow.Layer4{
						Protocol: &flow.Layer4_TCP{
							TCP: &flow.TCP{
								SourcePort:      a.src.Port(),
								DestinationPort: a.dst.Port(),
								Flags:           &observer.TCPFlags{SYN: true},
							},
						},
					},
				},
			},
		},
	}
	res = a.matchAllFlowRequirements(context.Background(), flows, "my-pod", egressFlowRequirements)
	assert.True(t, res.NeedMoreFlows)
	assert.Equal(t, 0, res.FirstMatch)
	assert.Equal(t, 0, res.LastMatch)
	assert.Equal(t, 1, len(res.Matched))
	assert.True(t, res.Matched[0])
}
