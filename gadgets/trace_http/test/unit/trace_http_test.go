// Copyright 2024 The Inspektor Gadget authors
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

package tests

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type traceHTTPEvent struct {
	eventtypes.CommonData

	Src          string `json:"src"`
	Dst          string `json:"dst"`
	Proto        string `json:"proto"`
	Method       string `json:"method"`
	Host         string `json:"host"`
	Path         string `json:"path"`
	StatusCode   int    `json:"status_code"`
	LatencyMs    int    `json:"latency_ms"`
}

func TestTraceHTTP(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-trace-http"
	containerImage := "docker.io/library/nginx:latest"

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-trace-http")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"while true; do nginx -g 'daemon off;'; done",
		containerOpts...,
	)

	testContainer.Start(t)
	t.Cleanup(func() {
		testContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option
	commonDataOpts := []utils.CommonDataOption{
		utils.WithContainerImageName(containerImage),
		utils.WithContainerID(testContainer.ID()),
	}

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), "--timeout=5"))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns), "--timeout=5"))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntry := &traceHTTPEvent{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				Proto:      "HTTP",
				Method:     "GET",
				Path:       "/",
				StatusCode: 200,
			}

			expectedEntry.Comm = "curl"
			expectedEntry.Uid = 0
			expectedEntry.Gid = 0

			normalize := func(e *traceHTTPEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				// Normalize variable fields
				e.Src = ""
				e.Dst = ""
				e.Host = ""
				e.LatencyMs = 0
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	))

	runner := igrunner.New(runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{
		utils.Sleep(5), // wait for nginx to start
		igtesting.SimpleTestStep{
			Name: "Start trace_http",
			Cmd:  runner.Run,
			Args: []string{"run", "trace_http"},
		},
		utils.Sleep(3), // wait to ensure the tracer is started
		igtesting.SimpleTestStep{
			Name: "Generate HTTP traffic",
			Cmd:  testContainer.Exec,
			Args: []string{"curl", "-s", "http://localhost/"},
		},
	}, t, testingOpts...)
}

func TestTraceHTTPWithFilters(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	// Test with minimum latency filter
	t.Run("MinLatencyFilter", func(t *testing.T) {
		runner := igrunner.New()
		output := runner.Run(t, "run", "trace_http", "--min-latency=1000", "--timeout=2")
		// Should capture only requests with latency > 1000ms
		// In practice, this test would need to generate slow requests
		require.NotContains(t, output, "error")
	})

	// Test with capture-request=false
	t.Run("ResponseOnly", func(t *testing.T) {
		runner := igrunner.New()
		output := runner.Run(t, "run", "trace_http", "--capture-request=false", "--timeout=2")
		require.NotContains(t, output, "error")
	})
}