//+build test_as_root

/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package integration

import (
	"os"
	"testing"
)

func TestRootUser(t *testing.T) {
	rootUID := 0
	actualUID := os.Geteuid()
	if actualUID != rootUID {
		t.Errorf("This test should be running as root, but it is not (UID: %v)", actualUID)
	}
}
