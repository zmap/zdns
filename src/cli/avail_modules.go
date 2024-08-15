/*
 * ZDNS Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package cli

import (
	"fmt"
	"github.com/spf13/cobra"
	"sort"
)

const (
	ColWidth      = 14
	ModulesPerRow = 4
)

var availModulesCmd = &cobra.Command{
	Use:   "avail-modules",
	Short: "List available modules",
	Long:  `Lists available modules for ZDNS, each of which performs a different type of lookup. All modules that are DNS query names send DNS querys of that type, while the others provide extra functionality.`,
	Run: func(cmd *cobra.Command, args []string) {
		// convert modules to slice
		modules := make([]string, 0, len(moduleToLookupModule))
		for module := range moduleToLookupModule {
			modules = append(modules, module)
		}
		// sort modules alphabetically
		sort.Strings(modules)
		// print in grid format for readability
		for i, module := range modules {
			fmt.Printf("%-*s", ColWidth, module)
			if (i+1)%ModulesPerRow == 0 {
				fmt.Println()
			}
		}

		// If the number of modules isn't a multiple of 4, ensure a final newline
		if len(modules)%ModulesPerRow != 0 {
			fmt.Println()
		}

	},
}

func init() {
	rootCmd.AddCommand(availModulesCmd)
}
