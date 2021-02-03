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
package app

import (
	"context"
	"testing"
)

func TestVersion(t *testing.T) {
	GitCommit = "3c9c1080d50ffd306213c3ea320e7856088d3ad8"
	GitTag = "v2.0"

	app := App{}

	versionResponse, err := app.Version(context.Background(), &VersionRequest{})

	if err != nil {
		t.Fatalf("Failed to retrieve version: %v", err)
	}

	if versionResponse.Commit != GitCommit {
		t.Fatalf("Version endpoint returned wrong commit. Expected: %v. Received: %v", GitCommit, versionResponse.Commit)
	}

	if versionResponse.Tag != GitTag {
		t.Fatalf("Version endpoint returned wrong tag. Expected: %v. Received: %v", GitTag, versionResponse.Tag)
	}
}
