/*
 * JuiceFS, Copyright 2022 Juicedata, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func GetKernelVersion() (major, minor int) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err == nil {
		buf := make([]byte, 0, 65) // Utsname.Release [65]int8
		for _, v := range uname.Release {
			if v == 0x00 {
				break
			}
			buf = append(buf, byte(v))
		}
		ps := strings.SplitN(string(buf), ".", 3)
		if len(ps) < 2 {
			return
		}
		if major, err = strconv.Atoi(ps[0]); err != nil {
			return
		}
		minor, _ = strconv.Atoi(ps[1])
	}
	return
}

func CheckExists(fileName string) bool {
	if _, err := os.Stat(fileName); err != nil {
		return false
	} else {
		return true
	}
}

const (
	procPath  = "/proc/version"
	osRelPath = "/etc/os-release"
	format    = `
Kernel: 
%s
LSB Release: 
%s
Processor: 
%s
OS Release: 
%s`
)

func GetEntry() (string, error) {
	var (
		kernel     string
		lsbRelease string
		processor  string
		osRelease  string
	)
	kernel, err := GetKernelInfo()
	if err != nil {
		return "", fmt.Errorf("failed to execute command `uname`: %s", err)
	}

	ret, err := exec.Command("lsb_release", "-a").Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute command `lsb_release`: %s", err)
	}

	lsbRelease = string(ret)

	if CheckExists(procPath) {
		ret, err := exec.Command("cat", procPath).Output()
		if err != nil {
			return "", fmt.Errorf("failed to execute command `cat %s`: %s", procPath, err)
		}
		processor = string(ret)
	}
	if CheckExists(osRelPath) {
		ret, err := exec.Command("cat", osRelPath).Output()
		if err != nil {
			return "", fmt.Errorf("failed to execute command `cat %s`: %s", osRelPath, err)
		}
		osRelease = string(ret)
	}

	return fmt.Sprintf(format, kernel, processor, lsbRelease, osRelease), nil
}
