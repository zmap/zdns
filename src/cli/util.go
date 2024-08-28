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
	"encoding/json"
	log "github.com/sirupsen/logrus"
)

// TODO this works - but we need to make it applicable to all other types of uints/ints
func replaceIntSliceInterface(data interface{}) interface{} {
	// special case
	if castedData, ok := data.([]uint8); ok {
		jsonData, err := json.Marshal(castedData)
		if err != nil {
			log.Errorf("unable to marshal data: %s", err)
		}
		return jsonData
	}
	// special case, data is []interface{} where each "interface{}" is a uint8
	// differs from above with the additional layer of indirection
	if castedData, ok := data.([]interface{}); ok {
		if len(castedData) == 0 {
			return data
		}
		if _, ok := castedData[0].(uint8); ok {
			ret := make([]uint8, len(castedData))
			for i, v := range castedData {
				ret[i] = v.(uint8)
			}
			jsonData, err := json.Marshal(ret)
			if err != nil {
				log.Errorf("unable to marshal data: %s", err)
			}
			return jsonData
		}
	}

	// map recursive case
	if castedData, ok := data.(map[string]interface{}); ok {
		for k, v := range castedData {
			if "Id" == k {
				log.Warn("raw")
			}
			castedData[k] = replaceIntSliceInterface(v)
		}
		return castedData
	}
	// slice recursive case
	if castedData, ok := data.([]interface{}); ok {
		for i, v := range castedData {
			castedData[i] = replaceIntSliceInterface(v)
		}
		return castedData
	}
	// general case
	return data
}

func isInt(data interface{}) bool {
	switch data.(type) {
	case int:
		return true
	case int8:
		return true
	case int16:
		return true
	case int32:
		return true
	case int64:
		return true
	case uint:
		return true
	case uint8:
		return true
	case uint16:
		return true
	case uint32:
		return true
	case uint64:
		return true
	}
	return false
}
