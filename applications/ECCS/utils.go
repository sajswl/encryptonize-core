// Copyright 2021 CYBERCRYPT
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
	"encoding/json"
	"fmt"
	"log"

	encryptonize "client"
)

// Fail wraps text using ansi escape codes to color the output RED
func Fail(text string) string {
	return fmt.Sprintf("\x1b[31;1m%s\x1b[0m", text)
}

// Info wraps text using ansi escape codes to color the output BLUE
func Info(text string) string {
	return fmt.Sprintf("\x1b[34;1m%s\x1b[0m", text)
}

func PrintStruct(response interface{}) {
	out, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(Info(string(out)))
}

func ReadScopes(scopesString string) ([]encryptonize.Scope, error) {
	scopes := make([]encryptonize.Scope, 0, len(scopesString))
	for _, scope := range scopesString {
		switch string(scope) {
		case "r":
			scopes = append(scopes, encryptonize.ScopeRead)
		case "c":
			scopes = append(scopes, encryptonize.ScopeCreate)
		case "u":
			scopes = append(scopes, encryptonize.ScopeUpdate)
		case "d":
			scopes = append(scopes, encryptonize.ScopeDelete)
		case "i":
			scopes = append(scopes, encryptonize.ScopeIndex)
		case "o":
			scopes = append(scopes, encryptonize.ScopeObjectPermissions)
		case "m":
			scopes = append(scopes, encryptonize.ScopeUserManagement)
		default:
			return nil, fmt.Errorf("Invalid scope %v", string(scope))
		}
	}
	return scopes, nil
}
