// Copyright 2019-2021 The Inspektor Gadget authors
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

package utils

import (
	"fmt"
)

// Kubernetes client

func WrapInErrSetupK8sClient(err error) error {
	return fmt.Errorf("setting up Kubernetes client: %w", err)
}

func WrapInErrListPods(err error) error {
	return fmt.Errorf("listing pods: %w", err)
}

// Parser

func WrapInErrParserCreate(err error) error {
	return fmt.Errorf("creating parser: %w", err)
}

// Arguments

func WrapInErrOutputModeNotSupported(mode string) error {
	return fmt.Errorf("%q output mode is not supported", mode)
}

func WrapInErrInvalidArg(arg string, err error) error {
	return fmt.Errorf("invalid argument '%s': %w", arg, err)
}

// JSON parsing

func WrapInErrUnmarshalOutput(err error, output string) error {
	return fmt.Errorf("unmarshaling output: %w\n%s", err, output)
}

func WrapInErrMarshalOutput(err error) error {
	return fmt.Errorf("marshaling output: %w", err)
}
