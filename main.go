/*
 * ZDNS Copyright 2016 Regents of the University of Michigan
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
	"github.com/zmap/zdns/cmd"
	_ "github.com/zmap/zdns/pkg/alookup"
	_ "github.com/zmap/zdns/pkg/axfr"
	_ "github.com/zmap/zdns/pkg/bindversion"
	_ "github.com/zmap/zdns/pkg/dmarc"
	_ "github.com/zmap/zdns/pkg/miekg"
	_ "github.com/zmap/zdns/pkg/mxlookup"
	_ "github.com/zmap/zdns/pkg/nslookup"
	_ "github.com/zmap/zdns/pkg/spf"
)

func main() {
	cmd.Execute()
}
