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

package utils

// #include <stdlib.h>
// #include "uacc.h"
import "C"

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"unsafe"
)

// This module concerns itself with updating the user account database and log on nodes
// that a client connects to with an interactive session.

// Due to thread safety design in glibc we must serialize all access to the accounting database.
var accountDb sync.Mutex

// Max length of username and hostname as defined by glibc.
var nameMaxLen = 255

// InteractiveSessionOpened writes a new entry to the utmp database with a tag of `USER_PROCESS`.
// This should be called when an interactive session is started.
//
// `username`: Name of the user the interactive session is running under.
// `hostname`: Name of the system the user is logged into.
// `remoteAddrV6`: IPv6 address of the remote host.
// `ttyName`: Name of the TTY without the `/dev/` prefix.
func InteractiveSessionOpened(username string, hostname string, remote net.IP, ttyName string) error {
	rawV6 := remote.To16()
	groupedV6 := [4]int32{}
	for i := range groupedV6 {
		groupedV6[i] = int32(binary.LittleEndian.Uint32(rawV6[i*4 : (i+1)*4]))
	}

	// String parameter validation.
	if len(username) > nameMaxLen {
		return errors.New(("username length exceeds OS limits"))
	} else if len(hostname) > nameMaxLen {
		return errors.New(("hostname length exceeds OS limits"))
	} else if len(ttyName) > (int)(C.max_len_tty_name()-1) {
		return errors.New(("tty name length exceeds OS limits"))
	}

	// Convert Go strings into C strings that we can pass over ffi.
	var CUsername = C.CString(username)
	defer C.free(unsafe.Pointer(CUsername))
	var CHostname = C.CString(hostname)
	defer C.free(unsafe.Pointer(CHostname))
	var CTtyName = C.CString(ttyName)
	defer C.free(unsafe.Pointer(CTtyName))

	// Convert IPv6 array into C integer format.
	var CInts = [4]C.int{}
	for i := 0; i < 4; i++ {
		CInts[i] = (C.int)(groupedV6[i])
	}

	accountDb.Lock()
	var status = C.uacc_add_utmp_entry(CUsername, CHostname, &CInts[0], CTtyName)
	accountDb.Unlock()

	if status == C.UACC_GET_TIME_ERROR {
		return errors.New("InteractiveSessionOpened gettimeofday failed")
	} else if status == C.UACC_UTMP_MISSING_PERMISSIONS {
		return errors.New("InteractiveSessionOpened missing permissions to write to utmp/wtmp")
	} else if status == C.UACC_UTMP_WRITE_ERROR {
		return errors.New("InteractiveSessionOpened failed to add entry to utmp database")
	}

	return nil
}

// InteractiveSessionClosed marks an entry in the utmp database as DEAD_PROCESS.
// This should be called when an interactive session exits.
//
// The `ttyName` parameter must be the name of the TTY without the `/dev/` prefix.
func InteractiveSessionClosed(ttyName string) error {
	// String parameter validation.
	if len(ttyName) > (int)(C.max_len_tty_name()-1) {
		return errors.New("tty name length exceeds OS limits")
	}

	// Convert Go strings into C strings that we can pass over ffi.
	var CTtyName = C.CString(ttyName)
	defer C.free(unsafe.Pointer(CTtyName))

	accountDb.Lock()
	var status = C.uacc_mark_utmp_entry_dead(CTtyName)
	accountDb.Unlock()

	if status == C.UACC_GET_TIME_ERROR {
		return errors.New("InteractiveSessionClosed gettimeofday failed")
	} else if status == C.UACC_UTMP_MISSING_PERMISSIONS {
		return errors.New("InteractiveSessionClosed missing permissions to write to utmp/wtmp")
	} else if status == C.UACC_UTMP_WRITE_ERROR {
		return errors.New("InteractiveSessionClosed failed to add entry to utmp database")
	} else if status == C.UACC_UTMP_READ_ERROR {
		return errors.New("InteractiveSessionClosed failed to read and search utmp database")
	}

	return nil
}
