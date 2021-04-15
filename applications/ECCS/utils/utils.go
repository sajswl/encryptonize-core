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

package utils

import (
	"fmt"
)

// Fail wraps text using ansi escape codes to color the output RED
func Fail(text string) string {
	return fmt.Sprintf("\x1b[31;1m%s\x1b[0m", text)
}

// Pass wraps text using ansi escape codes to color the output GREEN
func Pass(text string) string {
	return fmt.Sprintf("\x1b[32;1m%s\x1b[0m", text)
}

// Info wraps text using ansi escape codes to color the output BLUE
func Info(text string) string {
	return fmt.Sprintf("\x1b[34;1m%s\x1b[0m", text)
}

// Warning wraps text using ansi escape codes to color the output YELLOW
func Warning(text string) string {
	return fmt.Sprintf("\x1b[33;1m%s\x1b[0m", text)
}
