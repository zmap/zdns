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

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// replaceIntSliceInterface replaces all slices of ints/uints with a JSON byte slice in the input interface
// this is needed because if you marshal a slice of interface{}'s, where the interface{} objects are ints, it'll
// get outputted as a list of numbers instead of a base64 encoded byte slice. This function recursively traverses
// the input interface and replaces all slices of ints/uints with a JSON byte slice, or leaves the input interface
// unchanged if it doesn't contain any slices of ints/uints
func replaceIntSliceInterface(data interface{}) interface{} {
	// special case
	jsonData, err := marshalIntSlice(data)
	if err != nil {
		log.Errorf("error marshalling data in int slice: %v", err)
		return data
	} else if jsonData != nil {
		return jsonData
	}

	// map recursive case
	if castedData, ok := data.(map[string]interface{}); ok {
		for k, v := range castedData {
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

// marshalIntSlice marshals a slice of ints, uints, or interfaces containing ints or uints into a JSON byte slice
// If the input is not a slice of ints, uints, or interfaces containing ints or uints, it returns nil, nil
func marshalIntSlice(v interface{}) ([]byte, error) {
	switch v := v.(type) {
	case []int:
		return json.Marshal(v)
	case []int8:
		return json.Marshal(v)
	case []int16:
		return json.Marshal(v)
	case []int32:
		return json.Marshal(v)
	case []int64:
		return json.Marshal(v)
	case []uint:
		return json.Marshal(v)
	case []uint8:
		return v, nil
	case []uint16:
		return json.Marshal(v)
	case []uint32:
		return json.Marshal(v)
	case []uint64:
		return json.Marshal(v)
	case []interface{}:
		var ok bool
		if len(v) > 0 {
			// Check the type of the first element
			switch v[0].(type) {
			case int:
				converted := make([]int, len(v))
				for i, val := range v {
					converted[i], ok = val.(int)
					if !ok {
						return nil, errors.New("failed to convert interface to int")
					}
				}
				return json.Marshal(converted)
			case int8:
				converted := make([]int8, len(v))
				for i, val := range v {
					converted[i], ok = val.(int8)
					if !ok {
						return nil, errors.New("failed to convert interface to int8")
					}
				}
				return json.Marshal(converted)
			case int16:
				converted := make([]int16, len(v))
				for i, val := range v {
					converted[i], ok = val.(int16)
					if !ok {
						return nil, errors.New("failed to convert interface to int16")
					}
				}
				return json.Marshal(converted)
			case int32:
				converted := make([]int32, len(v))
				for i, val := range v {
					converted[i], ok = val.(int32)
					if !ok {
						return nil, errors.New("failed to convert interface to int32")
					}
				}
				return json.Marshal(converted)
			case int64:
				converted := make([]int64, len(v))
				for i, val := range v {
					converted[i], ok = val.(int64)
					if !ok {
						return nil, errors.New("failed to convert interface to int64")
					}
				}
				return json.Marshal(converted)
			case uint:
				converted := make([]uint, len(v))
				for i, val := range v {
					converted[i], ok = val.(uint)
					if !ok {
						return nil, errors.New("failed to convert interface to uint")
					}
				}
				return json.Marshal(converted)
			case uint8:
				converted := make([]byte, len(v))
				for i, val := range v {
					converted[i], ok = val.(byte)
				}
				if !ok {
					return nil, errors.New("failed to convert interface to byte (uint8)")
				}
				return converted, nil
			case uint16:
				converted := make([]uint16, len(v))
				for i, val := range v {
					converted[i], ok = val.(uint16)
					if !ok {
						return nil, errors.New("failed to convert interface to uint16")
					}
				}
				return json.Marshal(converted)
			case uint32:
				converted := make([]uint32, len(v))
				for i, val := range v {
					converted[i], ok = val.(uint32)
					if !ok {
						return nil, errors.New("failed to convert interface to uint32")
					}
				}
				return json.Marshal(converted)
			case uint64:
				converted := make([]uint64, len(v))
				for i, val := range v {
					converted[i], ok = val.(uint64)
					if !ok {
						return nil, errors.New("failed to convert interface to uint64")
					}
				}
				return json.Marshal(converted)
			default:
				return nil, nil
			}
		}
		return nil, nil
	default:
		return nil, nil
	}
}
