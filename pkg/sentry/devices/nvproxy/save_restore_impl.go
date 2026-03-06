// Copyright 2023 The gVisor Authors.
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

//go:build !false
// +build !false

package nvproxy

import (
	goContext "context"
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func (nvp *nvproxy) beforeSaveImpl() {
	nvp.clientsMu.RLock()
	defer nvp.clientsMu.RUnlock()
	if len(nvp.clients) != 0 {
		panic("can't save with live nvproxy clients")
	}
}

func (nvp *nvproxy) afterLoadImpl(goContext.Context) {
	// no-op
}

// nvidiaFDHolders walks all guest task FD tables and returns a description of
// which guest PIDs hold FDs whose impl matches the given predicate.
func nvidiaFDHolders(k *kernel.Kernel, match func(vfs.FileDescriptionImpl) bool) string {
	if k == nil {
		return "(kernel reference unavailable)"
	}
	ctx := context.Background()
	type holderInfo struct {
		pid kernel.ThreadID
		fds []int32
	}
	var holders []holderInfo
	seen := make(map[*kernel.FDTable]bool)
	k.TaskSet().ForEachThreadGroup(func(tg *kernel.ThreadGroup, leader *kernel.Task) {
		if leader == nil {
			return
		}
		fdTable := leader.FDTable()
		if fdTable == nil || seen[fdTable] {
			return
		}
		seen[fdTable] = true
		var matchedFDs []int32
		for _, guestFD := range fdTable.GetFDs(ctx) {
			file, _ := fdTable.Get(guestFD)
			if file == nil {
				continue
			}
			if match(file.Impl()) {
				matchedFDs = append(matchedFDs, guestFD)
			}
			file.DecRef(ctx)
		}
		if len(matchedFDs) > 0 {
			holders = append(holders, holderInfo{
				pid: leader.ThreadID(),
				fds: matchedFDs,
			})
		}
	})
	if len(holders) == 0 {
		return "(no guest processes found holding this FD)"
	}
	var sb strings.Builder
	for i, h := range holders {
		if i > 0 {
			sb.WriteString("; ")
		}
		fmt.Fprintf(&sb, "PID %d (guest fds %v)", h.pid, h.fds)
	}
	return sb.String()
}

func (fd *frontendFD) beforeSaveImpl() {
	holders := nvidiaFDHolders(fd.dev.nvp.k, func(impl vfs.FileDescriptionImpl) bool {
		return impl == fd
	})
	panic(fmt.Sprintf("nvproxy.frontendFD is not saveable (hostFD=%d, dev=%s); holders: %s", fd.hostFD, fd.dev.basename(), holders))
}

func (fd *frontendFD) afterLoadImpl(goContext.Context) {
	panic("nvproxy.frontendFD is not restorable")
}

func (fd *uvmFD) beforeSaveImpl() {
	holders := nvidiaFDHolders(fd.dev.nvp.k, func(impl vfs.FileDescriptionImpl) bool {
		return impl == fd
	})
	panic(fmt.Sprintf("nvproxy.uvmFD is not saveable (hostFD=%d); holders: %s", fd.hostFD, holders))
}

func (fd *uvmFD) afterLoadImpl(goContext.Context) {
	panic("nvproxy.uvmFD is not restorable")
}
