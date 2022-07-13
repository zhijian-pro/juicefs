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

package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/juicedata/juicefs/pkg/utils"

	"github.com/urfave/cli/v2"
)

var defaultOutDir = path.Join(".", "doctor")

const (
	defaultTraceTime   = 5
	defaultProfileTime = 30
)

func cmdDoctor() *cli.Command {
	return &cli.Command{
		Name:      "doctor",
		Action:    doctor,
		Category:  "INSPECTOR",
		ArgsUsage: "MOUNTPOINT",
		Usage:     "Collect and show system static and runtime information",
		Description: `
It collects and shares information from multiple dimensions such as the running environment and system logs, etc.

Examples:
$ juicefs doctor /mnt/jfs

# Result will be output to /var/log/
$ juicefs doctor --out-dir=/var/log /mnt/jfs

# Get log file up to 1000 entries
$ juicefs doctor --out-dir=/var/log --collect-log --limit=1000 /mnt/jfs

# Get pprof information
$ juicefs doctor --out-dir=/var/log --collect-log --limit=1000 --collect-pprof /mnt/jfs
`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "out-dir",
				Value: defaultOutDir,
				Usage: "the output directory of the result file",
			},
			&cli.BoolFlag{
				Name:  "collect-log",
				Usage: "enable log collection",
			},
			&cli.Uint64Flag{
				Name:  "limit",
				Usage: "the number of last entries to be collected",
			},
			&cli.BoolFlag{
				Name:  "collect-pprof",
				Usage: "enable pprof collection",
			},
			&cli.Uint64Flag{
				Name:  "trace-sec",
				Value: defaultTraceTime,
				Usage: "trace sampling duration",
			},
			&cli.Uint64Flag{
				Name:  "profile-sec",
				Value: defaultProfileTime,
				Usage: "profile sampling duration",
			},
		},
	}
}

func getVolumeConf(mp string) (string, error) {
	confPath := path.Join(mp, ".config")
	conf, err := os.ReadFile(confPath)
	if err != nil {
		return "", fmt.Errorf("error reading config %s: %v", confPath, err)
	}
	return string(conf), nil
}

func getCmdMount(mp string) (pid, cmd string, err error) {
	if !isUnix() {
		logger.Warnf("Failed to get command mount: %s is not supported", runtime.GOOS)
		return "", "", nil
	}

	ret, err := exec.Command("bash", "-c", "ps -ef | grep 'juicefs mount' | grep "+mp).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("failed to execute command `ps -ef | grep juicefs | grep %s`: %v", mp, err)
	}

	lines := strings.Split(string(ret), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) <= 7 {
			continue
		}
		cmdFields := fields[7:]
		flag := false
		for _, arg := range cmdFields {
			if mp == arg {
				flag = true
				break
			}
		}

		if flag {
			cmd = strings.Join(fields[7:], " ")
			pid = fields[1]
			break
		}
	}

	return pid, cmd, nil
}

func getDefaultLogDir() (string, error) {
	var defaultLogDir = "/var/log"
	switch runtime.GOOS {
	case "linux":
		if os.Getuid() == 0 {
			break
		}
		fallthrough
	case "darwin":
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("faild to get home directory")
		}
		defaultLogDir = path.Join(homeDir, ".juicefs")
	}
	return defaultLogDir, nil
}

var logArg = regexp.MustCompile(`--log([=|\s])(\S+)`)

func getLogPath(cmd string) (string, error) {
	if !isUnix() {
		logger.Warnf("Failed to get log path: %s is not supported", runtime.GOOS)
		return "", nil
	}

	var logPath string
	tmp := logArg.FindStringSubmatch(cmd)
	if len(tmp) == 3 {
		logPath = tmp[2]
	} else {
		defaultLogDir, err := getDefaultLogDir()
		if err != nil {
			return "", err
		}
		logPath = path.Join(defaultLogDir, "juicefs.log")
	}

	return logPath, nil
}

func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		logger.Fatalf("error closing log file %s: %v", file.Name(), err)
	}
}

// Multiline log is supported
var validLog = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}.\d{6}) .+\[(\d+)\] <(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|PANIC)>:([\s|\S])*\[(\w+).go:(\d+)\]`)

func copyLogFile(logPath, outDir, pid string, limit uint64) (fileName string, err error) {
	logFile, err := os.Open(logPath)
	if err != nil {
		return "", fmt.Errorf("error opening log file %s: %v", logPath, err)
	}
	defer closeFile(logFile)

	tmpPath := path.Join(outDir, uuid.New().String())
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return "", fmt.Errorf("error opening log file %s: %v", tmpPath, err)
	}
	defer closeFile(tmpFile)
	writer := bufio.NewWriter(tmpFile)

	if limit > 0 {
		st, err := logFile.Stat()
		if err != nil {
			return "", fmt.Errorf("failed to stat log file %s: %v", logPath, err)
		}

		size := st.Size()
		var offset int64 = -1
		char := make([]byte, 1)
		line := ""
		// read the file in reverse order
		for (-offset) <= size {
			if _, err := logFile.Seek(offset, io.SeekEnd); err != nil {
				logger.Fatalf("Failed to seek log file %s: %v", logPath, err)
			}
			if _, err = logFile.Read(char); err != nil {
				logger.Fatalf("Failed to read log file %s: %v", logPath, err)
			}

			if char[0] == '\n' && len(line) != 0 && validLog.MatchString(line) {
				field := strings.Fields(line)[2]
				currPid := strings.TrimRight(field[strings.Index(field, "[")+1:], "]")
				if currPid == pid {
					if _, err := fmt.Fprintf(writer, "%s\n", line); err != nil {
						logger.Fatalf("Failed to write log file: %v", err)
					}
					limit--
				}
				line = ""
				if limit == 0 {
					break
				}
			} else {
				line = string(char) + line
			}
			offset--
		}
	} else {
		reader := bufio.NewReader(logFile)
		if _, err := io.Copy(writer, reader); err != nil {
			return "", fmt.Errorf("failed to copy log file: %v", err)
		}
	}
	if err := writer.Flush(); err != nil {
		logger.Fatalf("Failed to flush writer: %v", err)
	}
	return tmpPath, nil
}

func getPprofPort(pid string) (int, error) {
	if !isUnix() {
		logger.Warnf("Failed to get pprof port: %s is not supported", runtime.GOOS)
		return 0, nil
	}

	cmdStr := "lsof -i -nP | grep LISTEN | grep " + pid
	if os.Getuid() == 0 {
		cmdStr = "sudo " + cmdStr
	}
	ret, err := exec.Command("bash", "-c", cmdStr).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("failed to execute command `ps -ef | grep juicefs`: %v", err)
	}
	lines := strings.Split(string(ret), "\n")
	if len(lines) == 0 {
		return 0, fmt.Errorf("pprof will be collected, but no listen port")
	}

	var listenPort = math.MaxInt
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 0 {
			port, err := strconv.Atoi(strings.Split(fields[len(fields)-2], ":")[1])
			if err != nil {
				logger.Errorf("failed to parse port %v: %v", port, err)
			}
			if port >= 6060 && port <= 6099 && port <= listenPort {
				listenPort = port
			}
		}
	}

	if listenPort == math.MaxInt {
		return 0, fmt.Errorf("no valid pprof port found")
	}
	return listenPort, nil
}

func getRequest(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error GET request: %v", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error GET request, status code %d", resp.StatusCode)
	}

	defer func(body io.ReadCloser) {
		if err := body.Close(); err != nil {
			logger.Errorf("error closing body: %v", err)
		}
	}(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	return body, nil
}

// check pprof service status
func checkAlive(port int, mp string) error {
	url := fmt.Sprintf("http://localhost:%d/debug/pprof/cmdline?debug=1", port)
	resp, err := getRequest(url)
	if err != nil {
		return fmt.Errorf("error checking pprof alive: %v", err)
	}
	resp = bytes.ReplaceAll(resp, []byte{0}, []byte{' '})
	fields := strings.Fields(string(resp))
	flag := false
	for _, field := range fields {
		if mp == field {
			flag = true
		}
	}
	if !flag {
		return fmt.Errorf("mount point mismatch: %s", resp)
	}

	return nil
}

func reqAndSaveMetric(name, url, outDir string) error {
	resp, err := getRequest(url)
	if err != nil {
		return fmt.Errorf("error getting metric: %v", err)
	}
	retPath := path.Join(outDir, fmt.Sprintf("juicefs.%s", name))
	retFile, err := os.Create(retPath)
	if err != nil {
		logger.Fatalf("error opening log file %s: %v", retPath, err)
	}
	defer closeFile(retFile)

	writer := bufio.NewWriter(retFile)
	if _, err := writer.Write(resp); err != nil {
		return fmt.Errorf("error writing metric %s: %v", name, err)
	}

	return nil
}

func isUnix() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin"
}

func doctor(ctx *cli.Context) error {
	currTime := time.Now().Format("20060102150405")
	setup(ctx, 1)
	mp := ctx.Args().First()
	inode, err := utils.GetFileInode(mp)
	if err != nil {
		return fmt.Errorf("lookup inode for %s: %s", mp, err)
	}
	if inode != 1 {
		return fmt.Errorf("path %s is not a mount point", mp)
	}

	outDir := ctx.String("out-dir")
	_, err = os.Stat(outDir)
	// special treatment for default out dir
	if os.IsNotExist(err) && outDir == defaultOutDir {
		logger.Warningf("out dir %s is not exist, created by default", outDir)
		if err := os.Mkdir(outDir, 0777); err != nil {
			return fmt.Errorf("failed to create out dir %s: %v", outDir, err)
		}
	}
	stat, err := os.Stat(outDir)
	if err != nil {
		return fmt.Errorf("failed to stat out dir %s: %v", outDir, err)
	}
	if !stat.IsDir() {
		return fmt.Errorf("argument --out-dir must be directory %s", outDir)
	}

	filePath := path.Join(outDir, fmt.Sprintf("system-info-%s.log", currTime))
	file, err := os.Create(filePath)
	defer closeFile(file)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", filePath, err)
	}

	osEntry, err := utils.GetEntry()
	if err != nil {
		return fmt.Errorf("failed to get system info: %v", err)
	}

	result := fmt.Sprintf(`Platform: 
%s %s
%s
JuiceFS Version:
%s`, runtime.GOOS, runtime.GOARCH, osEntry, ctx.App.Version)

	if _, err = file.WriteString(result); err != nil {
		return fmt.Errorf("failed to write system info %s: %v", filePath, err)
	}
	fmt.Printf("\nSystem Info:\n%s\n", result)

	mp, _ = filepath.Abs(mp)
	conf, err := getVolumeConf(mp)
	if err != nil {
		return err
	}
	prefix := strings.Trim(strings.Join(strings.Split(mp, "/"), "-"), "-")
	confPath := path.Join(outDir, fmt.Sprintf("%s-%s.config", prefix, currTime))
	confFile, err := os.Create(confPath)
	defer closeFile(confFile)
	if err != nil {
		return fmt.Errorf("failed to create config file %s: %v", confPath, err)
	}
	if _, err = confFile.WriteString(conf); err != nil {
		return fmt.Errorf("failed to write config %s: %v", confPath, err)
	}

	pid, cmd, err := getCmdMount(mp)
	if err != nil {
		return err
	}
	fmt.Printf("\nMount Command:\n%s\n", cmd)

	if ctx.Bool("collect-log") {
		logPath, err := getLogPath(cmd)
		if err != nil {
			return err
		}

		limit := ctx.Uint64("limit")
		tmpPath, err := copyLogFile(logPath, outDir, pid, limit)
		if err != nil {
			return fmt.Errorf("error copying log file: %v", err)
		}

		retLogPath := path.Join(outDir, fmt.Sprintf("%s-%s.log", prefix, currTime))
		if err := os.Rename(tmpPath, retLogPath); err != nil {
			return err
		}

		logger.Infof("Log %s is collected", logPath)
	}

	if ctx.Bool("collect-pprof") {
		port, err := getPprofPort(pid)
		if err != nil {
			return err
		}
		if port == 0 {
			return fmt.Errorf("invalid port: %v", port)
		}
		if err := checkAlive(port, mp); err != nil {
			return fmt.Errorf("pprof server %v is not alive", port)
		}

		baseUrl := fmt.Sprintf("http://localhost:%d/debug/pprof/", port)
		trace := ctx.Uint64("trace-sec")
		profile := ctx.Uint64("profile-sec")
		metrics := []struct{ name, url string }{
			{name: "allocs.pb.gz", url: "allocs"},
			{name: "block.pb.gz", url: "block"},
			{name: "cmdline.txt", url: "cmdline"},
			{name: "goroutine.pb.gz", url: "goroutine"},
			{name: "full.goroutine.stack.txt", url: "goroutine?debug=2"},
			{name: "heap.pb.gz", url: "heap"},
			{name: "mutex.pb.gz", url: "mutex"},
			{name: "threadcreate.pb.gz", url: "threadcreate"},
			{name: fmt.Sprintf("trace.%ds.pb.gz", trace), url: fmt.Sprintf("trace?seconds=%d", trace)},
			{name: fmt.Sprintf("profile.%ds.pb.gz", profile), url: fmt.Sprintf("profile?seconds=%d", profile)},
		}

		pprofOutDir := path.Join(outDir, fmt.Sprintf("pprof-%s-%s", prefix, currTime))
		if err := os.Mkdir(pprofOutDir, os.ModePerm); err != nil {
			return fmt.Errorf("error creating directory: %v", err)
		}

		var wg sync.WaitGroup
		for _, metric := range metrics {
			wg.Add(1)
			go func(metric struct{ name, url string }) {
				defer wg.Done()

				m := metric.name[:strings.Index(metric.name, ".")]
				if m == "profile" {
					logger.Infof("Metric profile is sampling, sampling time: %ds...", profile)
				}
				if m == "trace" {
					logger.Infof("Metric trace is sampling, sampling time: %ds...", trace)
				}
				if err := reqAndSaveMetric(metric.name, baseUrl+metric.url, pprofOutDir); err != nil {
					logger.Errorf("Error saving metric %s: %v", m, err)
				}

			}(metric)
		}
		wg.Wait()
	}

	return nil
}
