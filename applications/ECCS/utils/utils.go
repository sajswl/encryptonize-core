// Copyright 2020 CYBERCRYPT
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

// Used for displaying RED text
func Fail(text string) string {
	return fmt.Sprintf("\x1b[31;1m%s\x1b[0m", text)
}

// Used for displaying GREEN text
func Pass(text string) string {
	return fmt.Sprintf("\x1b[32;1m%s\x1b[0m", text)
}

// Used for displaying BLUE text
func Info(text string) string {
	return fmt.Sprintf("\x1b[34;1m%s\x1b[0m", text)
}

// Used for displaying YELLOW text
func Warning(text string) string {
	return fmt.Sprintf("\x1b[33;1m%s\x1b[0m", text)
}
