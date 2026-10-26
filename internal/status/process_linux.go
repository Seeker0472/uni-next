//go:build linux

package status

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func processIdentity(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	value := string(data)
	end := strings.LastIndex(value, ") ")
	if end < 0 {
		return "", errors.New("malformed process stat")
	}
	fields := strings.Fields(value[end+2:])
	if len(fields) <= 19 {
		return "", errors.New("process stat lacks start time")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", errors.New("invalid process start time")
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	boot := strings.TrimSpace(string(bootID))
	if boot == "" {
		return "", errors.New("empty boot identity")
	}
	return boot + "/" + fields[19], nil
}
