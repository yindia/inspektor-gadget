// Copyright 2023-2024 The Inspektor Gadget authors
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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/image"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"
)

var infoSkipCommands = []string{"version"}

func main() {
	if experimental.Enabled() {
		log.Info("Experimental features enabled")
	}

	rootCmd := &cobra.Command{
		Use:   filepath.Base(os.Args[0]),
		Short: "Collection of gadgets for containers",
	}
	common.AddConfigFlag(rootCmd)
	common.AddVerboseFlag(rootCmd)

	skipInfo := false
	for _, arg := range os.Args[1:] {
		for _, skipCmd := range infoSkipCommands {
			if strings.ToLower(arg) == skipCmd {
				skipInfo = true
			}
		}
	}

	rootCmd.AddCommand(common.NewVersionCmd())

	runtime := grpcruntime.New()

	// save the root flags for later use before we modify them (e.g. add runtime flags)
	rootFlags := commonutils.CopyFlagSet(rootCmd.PersistentFlags())

	runtimeGlobalParams := runtime.GlobalParamDescs().ToParams()
	common.AddFlags(rootCmd, runtimeGlobalParams, nil, runtime)
	err := runtime.Init(runtimeGlobalParams)
	if err != nil {
		log.Fatalf("initializing runtime: %v", err)
	}

	if !skipInfo {
		// evaluate flags early for runtimeGlobalFlags; this will make
		// sure that --remote-address has already been parsed when calling
		// GetInfo(), so it can target the specified address

		err := commonutils.ParseEarlyFlags(rootCmd, os.Args[1:])
		if err != nil {
			// Analogous to cobra error message
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		info, err := runtime.GetInfo()
		if err != nil {
			log.Warnf("Failed to load deploy info: %s", err)
		} else if err := commonutils.CheckServerVersionSkew(info.ServerVersion); err != nil {
			log.Warn(err.Error())
		}
	}

	// ensure that the runtime flags are set from the config file
	if err := common.InitConfig(rootFlags); err != nil {
		log.Fatalf("initializing config: %v", err)
	}
	if err = common.SetFlagsForParams(rootCmd, runtimeGlobalParams, config.RuntimeKey); err != nil {
		log.Fatalf("setting runtime flags from config: %v", err)
	}

	// add image subcommands to be added, for now only inspect is supported
	imgCommands := []*cobra.Command{
		image.NewInspectCmd(runtime),
	}

	hiddenColumnTags := []string{"kubernetes"}

	common.AddInstanceCommands(rootCmd, runtime)
	rootCmd.AddCommand(common.NewRunCommand(rootCmd, runtime, hiddenColumnTags, common.CommandModeRun))
	rootCmd.AddCommand(common.NewRunCommand(rootCmd, runtime, hiddenColumnTags, common.CommandModeAttach))
	rootCmd.AddCommand(common.NewConfigCmd(runtime, rootFlags))
	rootCmd.AddCommand(image.NewImageCmd(runtime, imgCommands))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	environment.Environment = environment.Local
}
