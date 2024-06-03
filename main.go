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
package main

import (
	"github.com/zmap/zdns/src/cli"
	// the order of these imports is important, as the modules are registered in the init() functions.
	// Import modules after the basic cmd pkg
	_ "github.com/zmap/zdns/src/modules/alookup"
	_ "github.com/zmap/zdns/src/modules/axfr"
	_ "github.com/zmap/zdns/src/modules/bindversion"
	_ "github.com/zmap/zdns/src/modules/dmarc"
	_ "github.com/zmap/zdns/src/modules/mxlookup"
	_ "github.com/zmap/zdns/src/modules/nslookup"
	_ "github.com/zmap/zdns/src/modules/spf"
)

func main() {
	cli.Execute()
}
