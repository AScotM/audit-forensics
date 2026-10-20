package main

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Record struct {
	Timestamp time.Time         `json:"timestamp"`
	Serial    string            `json:"serial"`
	Type      string            `json:"type"`
	Node      string            `json:"node,omitempty"`
	Fields    map[string]string `json:"fields"`
	Raw       string            `json:"raw,omitempty"`
	Source    string            `json:"source"`
	Line      int               `json:"line"`
}
type Event struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Node        string    `json:"node,omitempty"`
	Records     []Record  `json:"records"`
	Types       []string  `json:"types"`
	Subjects    []string  `json:"subjects,omitempty"`
	Executables []string  `json:"executables,omitempty"`
	Paths       []string  `json:"paths,omitempty"`
	Users       []string  `json:"users,omitempty"`
	Severity    string    `json:"severity"`
	Tags        []string  `json:"tags"`
	Findings    []Finding `json:"findings,omitempty"`
}
type Finding struct {
	Rule      string            `json:"rule"`
	Severity  string            `json:"severity"`
	Category  string            `json:"category"`
	Message   string            `json:"message"`
	EventID   string            `json:"event_id"`
	Timestamp time.Time         `json:"timestamp"`
	Evidence  map[string]string `json:"evidence,omitempty"`
}
type Rule struct {
	ID       string
	Category string
	Severity string
	Type     string
	Field    string
	Operator string
	Value    string
	Message  string
}
type Report struct {
	Generated      time.Time      `json:"generated"`
	Host           string         `json:"host"`
	Inputs         []string       `json:"inputs"`
	Records        int            `json:"records"`
	Events         int            `json:"events"`
	ParseErrors    int            `json:"parse_errors"`
	TypeCounts     map[string]int `json:"type_counts"`
	SeverityCounts map[string]int `json:"severity_counts"`
	CategoryCounts map[string]int `json:"category_counts"`
	Findings       []Finding      `json:"findings"`
	EventDetails   []Event        `json:"event_details,omitempty"`
	Warnings       []string       `json:"warnings,omitempty"`
}
type Options struct {
	Inputs        string
	Format        string
	Output        string
	Since         string
	Until         string
	Types         string
	Category      string
	Severity      string
	Search        string
	User          string
	Executable    string
	Node          string
	Limit         int
	MaxLine       int
	MaxEvents     int
	IncludeEvents bool
	IncludeRaw    bool
	Strict        bool
	Quiet         bool
	Sort          string
	Baseline      string
	SaveBaseline  string
	ListRules     bool
	ListTypes     bool
	Summary       bool
	Journal       bool
}

var messageRE = regexp.MustCompile(`(?:^|\s)msg=audit\(([0-9]+)(?:\.([0-9]+))?:([0-9]+)\)`)
var typeRE = regexp.MustCompile(`(?:^|\s)type=([^\s]+)`)
var nodeRE = regexp.MustCompile(`(?:^|\s)node=([^\s]+)`)
var hexRE = regexp.MustCompile(`^[0-9a-fA-F]+$`)
var auditRules = []Rule{
	{
		ID:       "AF-0001",
		Category: "selinux",
		Severity: "high",
		Type:     "AVC",
		Field:    "avc",
		Operator: "contains",
		Value:    "denied",
		Message:  "SELinux access denial (denied)",
	},
	{
		ID:       "AF-0002",
		Category: "authentication",
		Severity: "high",
		Type:     "USER_AUTH",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "Authentication attempt failed (failed)",
	},
	{
		ID:       "AF-0003",
		Category: "authentication",
		Severity: "high",
		Type:     "USER_LOGIN",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "Login failed (failed)",
	},
	{
		ID:       "AF-0004",
		Category: "authentication",
		Severity: "medium",
		Type:     "USER_ACCT",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "Account validation failed (failed)",
	},
	{
		ID:       "AF-0005",
		Category: "session",
		Severity: "info",
		Type:     "USER_START",
		Field:    "res",
		Operator: "equals",
		Value:    "success",
		Message:  "User session started (success)",
	},
	{
		ID:       "AF-0006",
		Category: "session",
		Severity: "info",
		Type:     "USER_END",
		Field:    "res",
		Operator: "equals",
		Value:    "success",
		Message:  "User session ended (success)",
	},
	{
		ID:       "AF-0007",
		Category: "privilege",
		Severity: "medium",
		Type:     "USER_CMD",
		Field:    "cmd",
		Operator: "exists",
		Value:    "",
		Message:  "Privileged user command observed ()",
	},
	{
		ID:       "AF-0008",
		Category: "credentials",
		Severity: "medium",
		Type:     "CRED_ACQ",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "Credential acquisition failed (failed)",
	},
	{
		ID:       "AF-0009",
		Category: "credentials",
		Severity: "medium",
		Type:     "CRED_DISP",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "Credential disposal failed (failed)",
	},
	{
		ID:       "AF-0010",
		Category: "credentials",
		Severity: "medium",
		Type:     "CRED_REFR",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "Credential refresh failed (failed)",
	},
	{
		ID:       "AF-0011",
		Category: "privilege",
		Severity: "high",
		Type:     "USER_ROLE_CHANGE",
		Field:    "res",
		Operator: "equals",
		Value:    "success",
		Message:  "Role change succeeded (success)",
	},
	{
		ID:       "AF-0012",
		Category: "identity",
		Severity: "medium",
		Type:     "USER_CHAUTHTOK",
		Field:    "res",
		Operator: "equals",
		Value:    "success",
		Message:  "Authentication token changed (success)",
	},
	{
		ID:       "AF-0013",
		Category: "identity",
		Severity: "high",
		Type:     "ADD_USER",
		Field:    "res",
		Operator: "equals",
		Value:    "success",
		Message:  "User added (success)",
	},
	{
		ID:       "AF-0014",
		Category: "identity",
		Severity: "high",
		Type:     "DEL_USER",
		Field:    "res",
		Operator: "equals",
		Value:    "success",
		Message:  "User deleted (success)",
	},
	{
		ID:       "AF-0015",
		Category: "identity",
		Severity: "high",
		Type:     "ADD_GROUP",
		Field:    "res",
		Operator: "equals",
		Value:    "success",
		Message:  "Group added (success)",
	},
	{
		ID:       "AF-0016",
		Category: "identity",
		Severity: "high",
		Type:     "DEL_GROUP",
		Field:    "res",
		Operator: "equals",
		Value:    "success",
		Message:  "Group deleted (success)",
	},
	{
		ID:       "AF-0017",
		Category: "identity",
		Severity: "medium",
		Type:     "CHGRP_ID",
		Field:    "res",
		Operator: "equals",
		Value:    "success",
		Message:  "Group identifier changed (success)",
	},
	{
		ID:       "AF-0018",
		Category: "identity",
		Severity: "medium",
		Type:     "CHUSER_ID",
		Field:    "res",
		Operator: "equals",
		Value:    "success",
		Message:  "User identifier changed (success)",
	},
	{
		ID:       "AF-0019",
		Category: "authentication",
		Severity: "medium",
		Type:     "GRP_AUTH",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "Group authentication failed (failed)",
	},
	{
		ID:       "AF-0020",
		Category: "identity",
		Severity: "medium",
		Type:     "GRP_MGMT",
		Field:    "res",
		Operator: "equals",
		Value:    "success",
		Message:  "Group membership modified (success)",
	},
	{
		ID:       "AF-0021",
		Category: "authentication",
		Severity: "medium",
		Type:     "LOGIN",
		Field:    "uid",
		Operator: "equals",
		Value:    "0",
		Message:  "Root login audit record (0)",
	},
	{
		ID:       "AF-0022",
		Category: "syscall",
		Severity: "high",
		Type:     "SYSCALL",
		Field:    "success",
		Operator: "equals",
		Value:    "no",
		Message:  "System call returned failure (no)",
	},
	{
		ID:       "AF-0023",
		Category: "execution",
		Severity: "medium",
		Type:     "EXECVE",
		Field:    "a0",
		Operator: "exists",
		Value:    "",
		Message:  "Process execution observed ()",
	},
	{
		ID:       "AF-0024",
		Category: "network",
		Severity: "info",
		Type:     "SOCKADDR",
		Field:    "saddr",
		Operator: "exists",
		Value:    "",
		Message:  "Socket address observed ()",
	},
	{
		ID:       "AF-0025",
		Category: "network",
		Severity: "high",
		Type:     "NETFILTER_CFG",
		Field:    "table",
		Operator: "exists",
		Value:    "",
		Message:  "Netfilter configuration changed ()",
	},
	{
		ID:       "AF-0026",
		Category: "network",
		Severity: "low",
		Type:     "NETFILTER_PKT",
		Field:    "hook",
		Operator: "exists",
		Value:    "",
		Message:  "Netfilter packet event ()",
	},
	{
		ID:       "AF-0027",
		Category: "audit-config",
		Severity: "high",
		Type:     "CONFIG_CHANGE",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "Audit configuration modified ()",
	},
	{
		ID:       "AF-0028",
		Category: "audit-config",
		Severity: "medium",
		Type:     "DAEMON_START",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "Audit daemon started ()",
	},
	{
		ID:       "AF-0029",
		Category: "audit-config",
		Severity: "high",
		Type:     "DAEMON_END",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "Audit daemon stopped ()",
	},
	{
		ID:       "AF-0030",
		Category: "audit-config",
		Severity: "critical",
		Type:     "DAEMON_ABORT",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "Audit daemon aborted ()",
	},
	{
		ID:       "AF-0031",
		Category: "audit-config",
		Severity: "high",
		Type:     "DAEMON_CONFIG",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "Audit daemon configuration updated ()",
	},
	{
		ID:       "AF-0032",
		Category: "selinux",
		Severity: "high",
		Type:     "MAC_POLICY_LOAD",
		Field:    "res",
		Operator: "equals",
		Value:    "success",
		Message:  "Mandatory access control policy loaded (success)",
	},
	{
		ID:       "AF-0033",
		Category: "selinux",
		Severity: "high",
		Type:     "MAC_STATUS",
		Field:    "enforcing",
		Operator: "equals",
		Value:    "0",
		Message:  "SELinux enforcing disabled (0)",
	},
	{
		ID:       "AF-0034",
		Category: "selinux",
		Severity: "high",
		Type:     "MAC_CONFIG_CHANGE",
		Field:    "res",
		Operator: "equals",
		Value:    "success",
		Message:  "Mandatory access control configuration changed (success)",
	},
	{
		ID:       "AF-0035",
		Category: "anomaly",
		Severity: "high",
		Type:     "ANOM_ABEND",
		Field:    "sig",
		Operator: "exists",
		Value:    "",
		Message:  "Process ended abnormally ()",
	},
	{
		ID:       "AF-0036",
		Category: "anomaly",
		Severity: "critical",
		Type:     "ANOM_PROMISCUOUS",
		Field:    "dev",
		Operator: "exists",
		Value:    "",
		Message:  "Network interface promiscuous mode changed ()",
	},
	{
		ID:       "AF-0037",
		Category: "anomaly",
		Severity: "medium",
		Type:     "ANOM_LINK",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "Suspicious link event ()",
	},
	{
		ID:       "AF-0038",
		Category: "anomaly",
		Severity: "high",
		Type:     "ANOM_LOGIN_FAILURES",
		Field:    "uid",
		Operator: "exists",
		Value:    "",
		Message:  "Repeated login failures detected by audit subsystem ()",
	},
	{
		ID:       "AF-0039",
		Category: "anomaly",
		Severity: "medium",
		Type:     "ANOM_LOGIN_TIME",
		Field:    "uid",
		Operator: "exists",
		Value:    "",
		Message:  "Login at unusual time ()",
	},
	{
		ID:       "AF-0040",
		Category: "anomaly",
		Severity: "medium",
		Type:     "ANOM_LOGIN_SESSIONS",
		Field:    "uid",
		Operator: "exists",
		Value:    "",
		Message:  "Excessive login sessions ()",
	},
	{
		ID:       "AF-0041",
		Category: "anomaly",
		Severity: "medium",
		Type:     "ANOM_LOGIN_ACCT",
		Field:    "uid",
		Operator: "exists",
		Value:    "",
		Message:  "Login account anomaly ()",
	},
	{
		ID:       "AF-0042",
		Category: "anomaly",
		Severity: "high",
		Type:     "ANOM_LOGIN_LOCATION",
		Field:    "uid",
		Operator: "exists",
		Value:    "",
		Message:  "Login location anomaly ()",
	},
	{
		ID:       "AF-0043",
		Category: "anomaly",
		Severity: "medium",
		Type:     "ANOM_MAX_DAC",
		Field:    "uid",
		Operator: "exists",
		Value:    "",
		Message:  "Discretionary access control anomaly ()",
	},
	{
		ID:       "AF-0044",
		Category: "anomaly",
		Severity: "high",
		Type:     "ANOM_MAX_MAC",
		Field:    "uid",
		Operator: "exists",
		Value:    "",
		Message:  "Mandatory access control anomaly ()",
	},
	{
		ID:       "AF-0045",
		Category: "anomaly",
		Severity: "high",
		Type:     "ANOM_MK_EXEC",
		Field:    "uid",
		Operator: "exists",
		Value:    "",
		Message:  "Executable creation anomaly ()",
	},
	{
		ID:       "AF-0046",
		Category: "anomaly",
		Severity: "high",
		Type:     "ANOM_MOD_ACCT",
		Field:    "uid",
		Operator: "exists",
		Value:    "",
		Message:  "Account modification anomaly ()",
	},
	{
		ID:       "AF-0047",
		Category: "anomaly",
		Severity: "high",
		Type:     "ANOM_ROOT_TRANS",
		Field:    "uid",
		Operator: "exists",
		Value:    "",
		Message:  "Root transition anomaly ()",
	},
	{
		ID:       "AF-0048",
		Category: "anomaly",
		Severity: "high",
		Type:     "ANOM_RBAC_FAIL",
		Field:    "uid",
		Operator: "exists",
		Value:    "",
		Message:  "Role based access control failure ()",
	},
	{
		ID:       "AF-0049",
		Category: "anomaly",
		Severity: "critical",
		Type:     "ANOM_RBAC_INTEGRITY_FAIL",
		Field:    "uid",
		Operator: "exists",
		Value:    "",
		Message:  "Role based access control integrity failure ()",
	},
	{
		ID:       "AF-0050",
		Category: "crypto",
		Severity: "high",
		Type:     "ANOM_CRYPTO_FAIL",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "Cryptographic operation failure ()",
	},
	{
		ID:       "AF-0051",
		Category: "crypto",
		Severity: "medium",
		Type:     "CRYPTO_KEY_USER",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "User cryptographic key operation failed (failed)",
	},
	{
		ID:       "AF-0052",
		Category: "crypto",
		Severity: "medium",
		Type:     "CRYPTO_SESSION",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "Cryptographic session failed (failed)",
	},
	{
		ID:       "AF-0053",
		Category: "crypto",
		Severity: "medium",
		Type:     "CRYPTO_TEST_USER",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "User cryptographic test failed (failed)",
	},
	{
		ID:       "AF-0054",
		Category: "integrity",
		Severity: "high",
		Type:     "INTEGRITY_DATA",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "Data integrity validation failed (failed)",
	},
	{
		ID:       "AF-0055",
		Category: "integrity",
		Severity: "high",
		Type:     "INTEGRITY_METADATA",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "Metadata integrity validation failed (failed)",
	},
	{
		ID:       "AF-0056",
		Category: "integrity",
		Severity: "medium",
		Type:     "INTEGRITY_STATUS",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "Integrity status failure (failed)",
	},
	{
		ID:       "AF-0057",
		Category: "integrity",
		Severity: "high",
		Type:     "INTEGRITY_RULE",
		Field:    "res",
		Operator: "equals",
		Value:    "failed",
		Message:  "Integrity policy rule failure (failed)",
	},
	{
		ID:       "AF-0058",
		Category: "privilege",
		Severity: "medium",
		Type:     "BPRM_FCAPS",
		Field:    "fp",
		Operator: "exists",
		Value:    "",
		Message:  "File capabilities applied during execution ()",
	},
	{
		ID:       "AF-0059",
		Category: "privilege",
		Severity: "high",
		Type:     "CAPSET",
		Field:    "cap_pi",
		Operator: "exists",
		Value:    "",
		Message:  "Process capability set modified ()",
	},
	{
		ID:       "AF-0060",
		Category: "sandbox",
		Severity: "high",
		Type:     "SECCOMP",
		Field:    "syscall",
		Operator: "exists",
		Value:    "",
		Message:  "Seccomp policy event ()",
	},
	{
		ID:       "AF-0061",
		Category: "kernel",
		Severity: "medium",
		Type:     "BPF",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "BPF program activity ()",
	},
	{
		ID:       "AF-0062",
		Category: "kernel",
		Severity: "high",
		Type:     "KERNEL_MODULE",
		Field:    "name",
		Operator: "exists",
		Value:    "",
		Message:  "Kernel module event ()",
	},
	{
		ID:       "AF-0063",
		Category: "kernel",
		Severity: "high",
		Type:     "MODULE_LOAD",
		Field:    "name",
		Operator: "exists",
		Value:    "",
		Message:  "Kernel module loaded ()",
	},
	{
		ID:       "AF-0064",
		Category: "kernel",
		Severity: "high",
		Type:     "MODULE_UNLOAD",
		Field:    "name",
		Operator: "exists",
		Value:    "",
		Message:  "Kernel module unloaded ()",
	},
	{
		ID:       "AF-0065",
		Category: "service",
		Severity: "info",
		Type:     "SERVICE_START",
		Field:    "unit",
		Operator: "exists",
		Value:    "",
		Message:  "Service started ()",
	},
	{
		ID:       "AF-0066",
		Category: "service",
		Severity: "medium",
		Type:     "SERVICE_STOP",
		Field:    "unit",
		Operator: "exists",
		Value:    "",
		Message:  "Service stopped ()",
	},
	{
		ID:       "AF-0067",
		Category: "software",
		Severity: "medium",
		Type:     "SOFTWARE_UPDATE",
		Field:    "sw",
		Operator: "exists",
		Value:    "",
		Message:  "Software update observed ()",
	},
	{
		ID:       "AF-0068",
		Category: "software",
		Severity: "medium",
		Type:     "SOFTWARE_INSTALL",
		Field:    "sw",
		Operator: "exists",
		Value:    "",
		Message:  "Software installation observed ()",
	},
	{
		ID:       "AF-0069",
		Category: "software",
		Severity: "medium",
		Type:     "SOFTWARE_REMOVE",
		Field:    "sw",
		Operator: "exists",
		Value:    "",
		Message:  "Software removal observed ()",
	},
	{
		ID:       "AF-0070",
		Category: "boot",
		Severity: "info",
		Type:     "SYSTEM_BOOT",
		Field:    "kernel",
		Operator: "exists",
		Value:    "",
		Message:  "System boot recorded ()",
	},
	{
		ID:       "AF-0071",
		Category: "boot",
		Severity: "info",
		Type:     "SYSTEM_SHUTDOWN",
		Field:    "kernel",
		Operator: "exists",
		Value:    "",
		Message:  "System shutdown recorded ()",
	},
	{
		ID:       "AF-0072",
		Category: "time",
		Severity: "medium",
		Type:     "TIME_ADJNTPVAL",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "NTP adjustment recorded ()",
	},
	{
		ID:       "AF-0073",
		Category: "time",
		Severity: "medium",
		Type:     "TIME_INJOFFSET",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "Time offset injected ()",
	},
	{
		ID:       "AF-0074",
		Category: "time",
		Severity: "medium",
		Type:     "TIME_ADJUST",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "System time adjusted ()",
	},
	{
		ID:       "AF-0075",
		Category: "system",
		Severity: "medium",
		Type:     "USYS_CONFIG",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "User-space system configuration changed ()",
	},
	{
		ID:       "AF-0076",
		Category: "virtualization",
		Severity: "medium",
		Type:     "VIRT_CONTROL",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "Virtualization control event ()",
	},
	{
		ID:       "AF-0077",
		Category: "virtualization",
		Severity: "info",
		Type:     "VIRT_MACHINE_ID",
		Field:    "vm",
		Operator: "exists",
		Value:    "",
		Message:  "Virtual machine identification ()",
	},
	{
		ID:       "AF-0078",
		Category: "virtualization",
		Severity: "medium",
		Type:     "VIRT_RESOURCE",
		Field:    "res",
		Operator: "exists",
		Value:    "",
		Message:  "Virtual resource operation ()",
	},
	{
		ID:       "AF-0079",
		Category: "virtualization",
		Severity: "medium",
		Type:     "VIRT_MIGRATE_IN",
		Field:    "vm",
		Operator: "exists",
		Value:    "",
		Message:  "Virtual machine migrated in ()",
	},
	{
		ID:       "AF-0080",
		Category: "virtualization",
		Severity: "medium",
		Type:     "VIRT_MIGRATE_OUT",
		Field:    "vm",
		Operator: "exists",
		Value:    "",
		Message:  "Virtual machine migrated out ()",
	},
	{
		ID:       "AF-0081",
		Category: "virtualization",
		Severity: "info",
		Type:     "VIRT_MACHINE_ID",
		Field:    "uuid",
		Operator: "exists",
		Value:    "",
		Message:  "Virtual machine UUID recorded ()",
	},
	{
		ID:       "AF-0082",
		Category: "session",
		Severity: "medium",
		Type:     "USER_TTY",
		Field:    "data",
		Operator: "exists",
		Value:    "",
		Message:  "Terminal input captured ()",
	},
	{
		ID:       "AF-0083",
		Category: "session",
		Severity: "medium",
		Type:     "TTY",
		Field:    "data",
		Operator: "exists",
		Value:    "",
		Message:  "TTY audit data recorded ()",
	},
	{
		ID:       "AF-0084",
		Category: "filesystem",
		Severity: "medium",
		Type:     "PATH",
		Field:    "nametype",
		Operator: "equals",
		Value:    "DELETE",
		Message:  "Filesystem path deleted (DELETE)",
	},
	{
		ID:       "AF-0085",
		Category: "filesystem",
		Severity: "medium",
		Type:     "PATH",
		Field:    "nametype",
		Operator: "equals",
		Value:    "CREATE",
		Message:  "Filesystem path created (CREATE)",
	},
	{
		ID:       "AF-0086",
		Category: "filesystem",
		Severity: "medium",
		Type:     "PATH",
		Field:    "nametype",
		Operator: "equals",
		Value:    "NORMAL",
		Message:  "Filesystem path accessed (NORMAL)",
	},
	{
		ID:       "AF-0087",
		Category: "execution",
		Severity: "info",
		Type:     "PROCTITLE",
		Field:    "proctitle",
		Operator: "exists",
		Value:    "",
		Message:  "Process title recorded ()",
	},
	{
		ID:       "AF-0088",
		Category: "process",
		Severity: "medium",
		Type:     "OBJ_PID",
		Field:    "op",
		Operator: "exists",
		Value:    "",
		Message:  "Process object operation ()",
	},
	{
		ID:       "AF-0089",
		Category: "process",
		Severity: "info",
		Type:     "FD_PAIR",
		Field:    "fd0",
		Operator: "exists",
		Value:    "",
		Message:  "File descriptor pair created ()",
	},
	{
		ID:       "AF-0090",
		Category: "memory",
		Severity: "medium",
		Type:     "MMAP",
		Field:    "fd",
		Operator: "exists",
		Value:    "",
		Message:  "Memory map audit record ()",
	},
	{
		ID:       "AF-0091",
		Category: "ipc",
		Severity: "medium",
		Type:     "IPC",
		Field:    "ouid",
		Operator: "exists",
		Value:    "",
		Message:  "Interprocess communication event ()",
	},
	{
		ID:       "AF-0092",
		Category: "ipc",
		Severity: "high",
		Type:     "IPC_SET_PERM",
		Field:    "ouid",
		Operator: "exists",
		Value:    "",
		Message:  "IPC permission changed ()",
	},
	{
		ID:       "AF-0093",
		Category: "kernel",
		Severity: "high",
		Type:     "FEATURE_CHANGE",
		Field:    "feature",
		Operator: "exists",
		Value:    "",
		Message:  "Kernel feature state changed ()",
	},
	{
		ID:       "AF-0094",
		Category: "kernel",
		Severity: "high",
		Type:     "KERN_MODULE",
		Field:    "name",
		Operator: "exists",
		Value:    "",
		Message:  "Kernel module event ()",
	},
	{
		ID:       "AF-0095",
		Category: "filesystem",
		Severity: "medium",
		Type:     "FANOTIFY",
		Field:    "resp",
		Operator: "exists",
		Value:    "",
		Message:  "Fanotify access decision ()",
	},
	{
		ID:       "AF-0096",
		Category: "sandbox",
		Severity: "high",
		Type:     "LANDLOCK_ACCESS",
		Field:    "access",
		Operator: "exists",
		Value:    "",
		Message:  "Landlock access decision ()",
	},
	{
		ID:       "AF-0097",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/passwd",
		Message:  "Sensitive filesystem path referenced (/etc/passwd)",
	},
	{
		ID:       "AF-0098",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/passwd",
		Message:  "Sensitive filesystem path referenced (/etc/passwd)",
	},
	{
		ID:       "AF-0099",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/shadow",
		Message:  "Sensitive filesystem path referenced (/etc/shadow)",
	},
	{
		ID:       "AF-0100",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/shadow",
		Message:  "Sensitive filesystem path referenced (/etc/shadow)",
	},
	{
		ID:       "AF-0101",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/group",
		Message:  "Sensitive filesystem path referenced (/etc/group)",
	},
	{
		ID:       "AF-0102",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/group",
		Message:  "Sensitive filesystem path referenced (/etc/group)",
	},
	{
		ID:       "AF-0103",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/gshadow",
		Message:  "Sensitive filesystem path referenced (/etc/gshadow)",
	},
	{
		ID:       "AF-0104",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/gshadow",
		Message:  "Sensitive filesystem path referenced (/etc/gshadow)",
	},
	{
		ID:       "AF-0105",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/sudoers",
		Message:  "Sensitive filesystem path referenced (/etc/sudoers)",
	},
	{
		ID:       "AF-0106",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/sudoers",
		Message:  "Sensitive filesystem path referenced (/etc/sudoers)",
	},
	{
		ID:       "AF-0107",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/sudoers.d",
		Message:  "Sensitive filesystem path referenced (/etc/sudoers.d)",
	},
	{
		ID:       "AF-0108",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/sudoers.d",
		Message:  "Sensitive filesystem path referenced (/etc/sudoers.d)",
	},
	{
		ID:       "AF-0109",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/ssh/sshd_config",
		Message:  "Sensitive filesystem path referenced (/etc/ssh/sshd_config)",
	},
	{
		ID:       "AF-0110",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/ssh/sshd_config",
		Message:  "Sensitive filesystem path referenced (/etc/ssh/sshd_config)",
	},
	{
		ID:       "AF-0111",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/ssh/ssh_config",
		Message:  "Sensitive filesystem path referenced (/etc/ssh/ssh_config)",
	},
	{
		ID:       "AF-0112",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/ssh/ssh_config",
		Message:  "Sensitive filesystem path referenced (/etc/ssh/ssh_config)",
	},
	{
		ID:       "AF-0113",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/selinux/config",
		Message:  "Sensitive filesystem path referenced (/etc/selinux/config)",
	},
	{
		ID:       "AF-0114",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/selinux/config",
		Message:  "Sensitive filesystem path referenced (/etc/selinux/config)",
	},
	{
		ID:       "AF-0115",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/audit/auditd.conf",
		Message:  "Sensitive filesystem path referenced (/etc/audit/auditd.conf)",
	},
	{
		ID:       "AF-0116",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/audit/auditd.conf",
		Message:  "Sensitive filesystem path referenced (/etc/audit/auditd.conf)",
	},
	{
		ID:       "AF-0117",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/audit/rules.d",
		Message:  "Sensitive filesystem path referenced (/etc/audit/rules.d)",
	},
	{
		ID:       "AF-0118",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/audit/rules.d",
		Message:  "Sensitive filesystem path referenced (/etc/audit/rules.d)",
	},
	{
		ID:       "AF-0119",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/systemd/system",
		Message:  "Sensitive filesystem path referenced (/etc/systemd/system)",
	},
	{
		ID:       "AF-0120",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/systemd/system",
		Message:  "Sensitive filesystem path referenced (/etc/systemd/system)",
	},
	{
		ID:       "AF-0121",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/usr/lib/systemd/system",
		Message:  "Sensitive filesystem path referenced (/usr/lib/systemd/system)",
	},
	{
		ID:       "AF-0122",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/usr/lib/systemd/system",
		Message:  "Sensitive filesystem path referenced (/usr/lib/systemd/system)",
	},
	{
		ID:       "AF-0123",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/boot",
		Message:  "Sensitive filesystem path referenced (/boot)",
	},
	{
		ID:       "AF-0124",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/boot",
		Message:  "Sensitive filesystem path referenced (/boot)",
	},
	{
		ID:       "AF-0125",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/boot/loader",
		Message:  "Sensitive filesystem path referenced (/boot/loader)",
	},
	{
		ID:       "AF-0126",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/boot/loader",
		Message:  "Sensitive filesystem path referenced (/boot/loader)",
	},
	{
		ID:       "AF-0127",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/default/grub",
		Message:  "Sensitive filesystem path referenced (/etc/default/grub)",
	},
	{
		ID:       "AF-0128",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/default/grub",
		Message:  "Sensitive filesystem path referenced (/etc/default/grub)",
	},
	{
		ID:       "AF-0129",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/grub2.cfg",
		Message:  "Sensitive filesystem path referenced (/etc/grub2.cfg)",
	},
	{
		ID:       "AF-0130",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/grub2.cfg",
		Message:  "Sensitive filesystem path referenced (/etc/grub2.cfg)",
	},
	{
		ID:       "AF-0131",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/cron.d",
		Message:  "Sensitive filesystem path referenced (/etc/cron.d)",
	},
	{
		ID:       "AF-0132",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/cron.d",
		Message:  "Sensitive filesystem path referenced (/etc/cron.d)",
	},
	{
		ID:       "AF-0133",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/crontab",
		Message:  "Sensitive filesystem path referenced (/etc/crontab)",
	},
	{
		ID:       "AF-0134",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/crontab",
		Message:  "Sensitive filesystem path referenced (/etc/crontab)",
	},
	{
		ID:       "AF-0135",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/var/spool/cron",
		Message:  "Sensitive filesystem path referenced (/var/spool/cron)",
	},
	{
		ID:       "AF-0136",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/var/spool/cron",
		Message:  "Sensitive filesystem path referenced (/var/spool/cron)",
	},
	{
		ID:       "AF-0137",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/pam.d",
		Message:  "Sensitive filesystem path referenced (/etc/pam.d)",
	},
	{
		ID:       "AF-0138",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/pam.d",
		Message:  "Sensitive filesystem path referenced (/etc/pam.d)",
	},
	{
		ID:       "AF-0139",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/security",
		Message:  "Sensitive filesystem path referenced (/etc/security)",
	},
	{
		ID:       "AF-0140",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/security",
		Message:  "Sensitive filesystem path referenced (/etc/security)",
	},
	{
		ID:       "AF-0141",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/hosts",
		Message:  "Sensitive filesystem path referenced (/etc/hosts)",
	},
	{
		ID:       "AF-0142",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/hosts",
		Message:  "Sensitive filesystem path referenced (/etc/hosts)",
	},
	{
		ID:       "AF-0143",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/resolv.conf",
		Message:  "Sensitive filesystem path referenced (/etc/resolv.conf)",
	},
	{
		ID:       "AF-0144",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/resolv.conf",
		Message:  "Sensitive filesystem path referenced (/etc/resolv.conf)",
	},
	{
		ID:       "AF-0145",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/nsswitch.conf",
		Message:  "Sensitive filesystem path referenced (/etc/nsswitch.conf)",
	},
	{
		ID:       "AF-0146",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/nsswitch.conf",
		Message:  "Sensitive filesystem path referenced (/etc/nsswitch.conf)",
	},
	{
		ID:       "AF-0147",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/ld.so.preload",
		Message:  "Sensitive filesystem path referenced (/etc/ld.so.preload)",
	},
	{
		ID:       "AF-0148",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/ld.so.preload",
		Message:  "Sensitive filesystem path referenced (/etc/ld.so.preload)",
	},
	{
		ID:       "AF-0149",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/ld.so.conf",
		Message:  "Sensitive filesystem path referenced (/etc/ld.so.conf)",
	},
	{
		ID:       "AF-0150",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/ld.so.conf",
		Message:  "Sensitive filesystem path referenced (/etc/ld.so.conf)",
	},
	{
		ID:       "AF-0151",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/modprobe.d",
		Message:  "Sensitive filesystem path referenced (/etc/modprobe.d)",
	},
	{
		ID:       "AF-0152",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/modprobe.d",
		Message:  "Sensitive filesystem path referenced (/etc/modprobe.d)",
	},
	{
		ID:       "AF-0153",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/modules-load.d",
		Message:  "Sensitive filesystem path referenced (/etc/modules-load.d)",
	},
	{
		ID:       "AF-0154",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/modules-load.d",
		Message:  "Sensitive filesystem path referenced (/etc/modules-load.d)",
	},
	{
		ID:       "AF-0155",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/sysctl.conf",
		Message:  "Sensitive filesystem path referenced (/etc/sysctl.conf)",
	},
	{
		ID:       "AF-0156",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/sysctl.conf",
		Message:  "Sensitive filesystem path referenced (/etc/sysctl.conf)",
	},
	{
		ID:       "AF-0157",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/sysctl.d",
		Message:  "Sensitive filesystem path referenced (/etc/sysctl.d)",
	},
	{
		ID:       "AF-0158",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/sysctl.d",
		Message:  "Sensitive filesystem path referenced (/etc/sysctl.d)",
	},
	{
		ID:       "AF-0159",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/firewalld",
		Message:  "Sensitive filesystem path referenced (/etc/firewalld)",
	},
	{
		ID:       "AF-0160",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/firewalld",
		Message:  "Sensitive filesystem path referenced (/etc/firewalld)",
	},
	{
		ID:       "AF-0161",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/NetworkManager",
		Message:  "Sensitive filesystem path referenced (/etc/NetworkManager)",
	},
	{
		ID:       "AF-0162",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/NetworkManager",
		Message:  "Sensitive filesystem path referenced (/etc/NetworkManager)",
	},
	{
		ID:       "AF-0163",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/containers",
		Message:  "Sensitive filesystem path referenced (/etc/containers)",
	},
	{
		ID:       "AF-0164",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/containers",
		Message:  "Sensitive filesystem path referenced (/etc/containers)",
	},
	{
		ID:       "AF-0165",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/pki",
		Message:  "Sensitive filesystem path referenced (/etc/pki)",
	},
	{
		ID:       "AF-0166",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/pki",
		Message:  "Sensitive filesystem path referenced (/etc/pki)",
	},
	{
		ID:       "AF-0167",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/ssl",
		Message:  "Sensitive filesystem path referenced (/etc/ssl)",
	},
	{
		ID:       "AF-0168",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/ssl",
		Message:  "Sensitive filesystem path referenced (/etc/ssl)",
	},
	{
		ID:       "AF-0169",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/root/.ssh",
		Message:  "Sensitive filesystem path referenced (/root/.ssh)",
	},
	{
		ID:       "AF-0170",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/root/.ssh",
		Message:  "Sensitive filesystem path referenced (/root/.ssh)",
	},
	{
		ID:       "AF-0171",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/.ssh/authorized_keys",
		Message:  "Sensitive filesystem path referenced (/.ssh/authorized_keys)",
	},
	{
		ID:       "AF-0172",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/.ssh/authorized_keys",
		Message:  "Sensitive filesystem path referenced (/.ssh/authorized_keys)",
	},
	{
		ID:       "AF-0173",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/fstab",
		Message:  "Sensitive filesystem path referenced (/etc/fstab)",
	},
	{
		ID:       "AF-0174",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/fstab",
		Message:  "Sensitive filesystem path referenced (/etc/fstab)",
	},
	{
		ID:       "AF-0175",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/crypttab",
		Message:  "Sensitive filesystem path referenced (/etc/crypttab)",
	},
	{
		ID:       "AF-0176",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/crypttab",
		Message:  "Sensitive filesystem path referenced (/etc/crypttab)",
	},
	{
		ID:       "AF-0177",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/lvm",
		Message:  "Sensitive filesystem path referenced (/etc/lvm)",
	},
	{
		ID:       "AF-0178",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/lvm",
		Message:  "Sensitive filesystem path referenced (/etc/lvm)",
	},
	{
		ID:       "AF-0179",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/var/lib/rpm",
		Message:  "Sensitive filesystem path referenced (/var/lib/rpm)",
	},
	{
		ID:       "AF-0180",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/var/lib/rpm",
		Message:  "Sensitive filesystem path referenced (/var/lib/rpm)",
	},
	{
		ID:       "AF-0181",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/var/lib/dnf",
		Message:  "Sensitive filesystem path referenced (/var/lib/dnf)",
	},
	{
		ID:       "AF-0182",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/var/lib/dnf",
		Message:  "Sensitive filesystem path referenced (/var/lib/dnf)",
	},
	{
		ID:       "AF-0183",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/yum.repos.d",
		Message:  "Sensitive filesystem path referenced (/etc/yum.repos.d)",
	},
	{
		ID:       "AF-0184",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/yum.repos.d",
		Message:  "Sensitive filesystem path referenced (/etc/yum.repos.d)",
	},
	{
		ID:       "AF-0185",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/profile",
		Message:  "Sensitive filesystem path referenced (/etc/profile)",
	},
	{
		ID:       "AF-0186",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/profile",
		Message:  "Sensitive filesystem path referenced (/etc/profile)",
	},
	{
		ID:       "AF-0187",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/profile.d",
		Message:  "Sensitive filesystem path referenced (/etc/profile.d)",
	},
	{
		ID:       "AF-0188",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/profile.d",
		Message:  "Sensitive filesystem path referenced (/etc/profile.d)",
	},
	{
		ID:       "AF-0189",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/bashrc",
		Message:  "Sensitive filesystem path referenced (/etc/bashrc)",
	},
	{
		ID:       "AF-0190",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/bashrc",
		Message:  "Sensitive filesystem path referenced (/etc/bashrc)",
	},
	{
		ID:       "AF-0191",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/environment",
		Message:  "Sensitive filesystem path referenced (/etc/environment)",
	},
	{
		ID:       "AF-0192",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/environment",
		Message:  "Sensitive filesystem path referenced (/etc/environment)",
	},
	{
		ID:       "AF-0193",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/login.defs",
		Message:  "Sensitive filesystem path referenced (/etc/login.defs)",
	},
	{
		ID:       "AF-0194",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/login.defs",
		Message:  "Sensitive filesystem path referenced (/etc/login.defs)",
	},
	{
		ID:       "AF-0195",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/securetty",
		Message:  "Sensitive filesystem path referenced (/etc/securetty)",
	},
	{
		ID:       "AF-0196",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/securetty",
		Message:  "Sensitive filesystem path referenced (/etc/securetty)",
	},
	{
		ID:       "AF-0197",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/rsyslog.conf",
		Message:  "Sensitive filesystem path referenced (/etc/rsyslog.conf)",
	},
	{
		ID:       "AF-0198",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/rsyslog.conf",
		Message:  "Sensitive filesystem path referenced (/etc/rsyslog.conf)",
	},
	{
		ID:       "AF-0199",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/rsyslog.d",
		Message:  "Sensitive filesystem path referenced (/etc/rsyslog.d)",
	},
	{
		ID:       "AF-0200",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/etc/rsyslog.d",
		Message:  "Sensitive filesystem path referenced (/etc/rsyslog.d)",
	},
	{
		ID:       "AF-0201",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/var/log/audit",
		Message:  "Sensitive filesystem path referenced (/var/log/audit)",
	},
	{
		ID:       "AF-0202",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/var/log/audit",
		Message:  "Sensitive filesystem path referenced (/var/log/audit)",
	},
	{
		ID:       "AF-0203",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/var/log/secure",
		Message:  "Sensitive filesystem path referenced (/var/log/secure)",
	},
	{
		ID:       "AF-0204",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/var/log/secure",
		Message:  "Sensitive filesystem path referenced (/var/log/secure)",
	},
	{
		ID:       "AF-0205",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/var/log/messages",
		Message:  "Sensitive filesystem path referenced (/var/log/messages)",
	},
	{
		ID:       "AF-0206",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/var/log/messages",
		Message:  "Sensitive filesystem path referenced (/var/log/messages)",
	},
	{
		ID:       "AF-0207",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/usr/local/bin",
		Message:  "Sensitive filesystem path referenced (/usr/local/bin)",
	},
	{
		ID:       "AF-0208",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/usr/local/bin",
		Message:  "Sensitive filesystem path referenced (/usr/local/bin)",
	},
	{
		ID:       "AF-0209",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/usr/local/sbin",
		Message:  "Sensitive filesystem path referenced (/usr/local/sbin)",
	},
	{
		ID:       "AF-0210",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/usr/local/sbin",
		Message:  "Sensitive filesystem path referenced (/usr/local/sbin)",
	},
	{
		ID:       "AF-0211",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/tmp",
		Message:  "Sensitive filesystem path referenced (/tmp)",
	},
	{
		ID:       "AF-0212",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/tmp",
		Message:  "Sensitive filesystem path referenced (/tmp)",
	},
	{
		ID:       "AF-0213",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/var/tmp",
		Message:  "Sensitive filesystem path referenced (/var/tmp)",
	},
	{
		ID:       "AF-0214",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/var/tmp",
		Message:  "Sensitive filesystem path referenced (/var/tmp)",
	},
	{
		ID:       "AF-0215",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/dev/shm",
		Message:  "Sensitive filesystem path referenced (/dev/shm)",
	},
	{
		ID:       "AF-0216",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/dev/shm",
		Message:  "Sensitive filesystem path referenced (/dev/shm)",
	},
	{
		ID:       "AF-0217",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/run",
		Message:  "Sensitive filesystem path referenced (/run)",
	},
	{
		ID:       "AF-0218",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/run",
		Message:  "Sensitive filesystem path referenced (/run)",
	},
	{
		ID:       "AF-0219",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/proc/sys",
		Message:  "Sensitive filesystem path referenced (/proc/sys)",
	},
	{
		ID:       "AF-0220",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/proc/sys",
		Message:  "Sensitive filesystem path referenced (/proc/sys)",
	},
	{
		ID:       "AF-0221",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/sys/kernel/security",
		Message:  "Sensitive filesystem path referenced (/sys/kernel/security)",
	},
	{
		ID:       "AF-0222",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/sys/kernel/security",
		Message:  "Sensitive filesystem path referenced (/sys/kernel/security)",
	},
	{
		ID:       "AF-0223",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/sys/fs/cgroup",
		Message:  "Sensitive filesystem path referenced (/sys/fs/cgroup)",
	},
	{
		ID:       "AF-0224",
		Category: "sensitive-path",
		Severity: "medium",
		Type:     "PATH",
		Field:    "path",
		Operator: "contains",
		Value:    "/sys/fs/cgroup",
		Message:  "Sensitive filesystem path referenced (/sys/fs/cgroup)",
	},
	{
		ID:       "AF-0225",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/sudo",
		Message:  "Security-relevant executable observed (/usr/bin/sudo)",
	},
	{
		ID:       "AF-0226",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "sudo",
		Message:  "Security-relevant executable observed (sudo)",
	},
	{
		ID:       "AF-0227",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/su",
		Message:  "Security-relevant executable observed (/usr/bin/su)",
	},
	{
		ID:       "AF-0228",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "su",
		Message:  "Security-relevant executable observed (su)",
	},
	{
		ID:       "AF-0229",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/passwd",
		Message:  "Security-relevant executable observed (/usr/bin/passwd)",
	},
	{
		ID:       "AF-0230",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "passwd",
		Message:  "Security-relevant executable observed (passwd)",
	},
	{
		ID:       "AF-0231",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/chage",
		Message:  "Security-relevant executable observed (/usr/bin/chage)",
	},
	{
		ID:       "AF-0232",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "chage",
		Message:  "Security-relevant executable observed (chage)",
	},
	{
		ID:       "AF-0233",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/useradd",
		Message:  "Security-relevant executable observed (/usr/sbin/useradd)",
	},
	{
		ID:       "AF-0234",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "useradd",
		Message:  "Security-relevant executable observed (useradd)",
	},
	{
		ID:       "AF-0235",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/userdel",
		Message:  "Security-relevant executable observed (/usr/sbin/userdel)",
	},
	{
		ID:       "AF-0236",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "userdel",
		Message:  "Security-relevant executable observed (userdel)",
	},
	{
		ID:       "AF-0237",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/usermod",
		Message:  "Security-relevant executable observed (/usr/sbin/usermod)",
	},
	{
		ID:       "AF-0238",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "usermod",
		Message:  "Security-relevant executable observed (usermod)",
	},
	{
		ID:       "AF-0239",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/groupadd",
		Message:  "Security-relevant executable observed (/usr/sbin/groupadd)",
	},
	{
		ID:       "AF-0240",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "groupadd",
		Message:  "Security-relevant executable observed (groupadd)",
	},
	{
		ID:       "AF-0241",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/groupdel",
		Message:  "Security-relevant executable observed (/usr/sbin/groupdel)",
	},
	{
		ID:       "AF-0242",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "groupdel",
		Message:  "Security-relevant executable observed (groupdel)",
	},
	{
		ID:       "AF-0243",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/chmod",
		Message:  "Security-relevant executable observed (/usr/bin/chmod)",
	},
	{
		ID:       "AF-0244",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "chmod",
		Message:  "Security-relevant executable observed (chmod)",
	},
	{
		ID:       "AF-0245",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/chown",
		Message:  "Security-relevant executable observed (/usr/bin/chown)",
	},
	{
		ID:       "AF-0246",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "chown",
		Message:  "Security-relevant executable observed (chown)",
	},
	{
		ID:       "AF-0247",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/setfacl",
		Message:  "Security-relevant executable observed (/usr/bin/setfacl)",
	},
	{
		ID:       "AF-0248",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "setfacl",
		Message:  "Security-relevant executable observed (setfacl)",
	},
	{
		ID:       "AF-0249",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/setcap",
		Message:  "Security-relevant executable observed (/usr/bin/setcap)",
	},
	{
		ID:       "AF-0250",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "setcap",
		Message:  "Security-relevant executable observed (setcap)",
	},
	{
		ID:       "AF-0251",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/setenforce",
		Message:  "Security-relevant executable observed (/usr/sbin/setenforce)",
	},
	{
		ID:       "AF-0252",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "setenforce",
		Message:  "Security-relevant executable observed (setenforce)",
	},
	{
		ID:       "AF-0253",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/semanage",
		Message:  "Security-relevant executable observed (/usr/sbin/semanage)",
	},
	{
		ID:       "AF-0254",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "semanage",
		Message:  "Security-relevant executable observed (semanage)",
	},
	{
		ID:       "AF-0255",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/semodule",
		Message:  "Security-relevant executable observed (/usr/sbin/semodule)",
	},
	{
		ID:       "AF-0256",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "semodule",
		Message:  "Security-relevant executable observed (semodule)",
	},
	{
		ID:       "AF-0257",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/auditctl",
		Message:  "Security-relevant executable observed (/usr/sbin/auditctl)",
	},
	{
		ID:       "AF-0258",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "auditctl",
		Message:  "Security-relevant executable observed (auditctl)",
	},
	{
		ID:       "AF-0259",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/augenrules",
		Message:  "Security-relevant executable observed (/usr/sbin/augenrules)",
	},
	{
		ID:       "AF-0260",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "augenrules",
		Message:  "Security-relevant executable observed (augenrules)",
	},
	{
		ID:       "AF-0261",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/systemctl",
		Message:  "Security-relevant executable observed (/usr/bin/systemctl)",
	},
	{
		ID:       "AF-0262",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "systemctl",
		Message:  "Security-relevant executable observed (systemctl)",
	},
	{
		ID:       "AF-0263",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/loginctl",
		Message:  "Security-relevant executable observed (/usr/bin/loginctl)",
	},
	{
		ID:       "AF-0264",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "loginctl",
		Message:  "Security-relevant executable observed (loginctl)",
	},
	{
		ID:       "AF-0265",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/journalctl",
		Message:  "Security-relevant executable observed (/usr/bin/journalctl)",
	},
	{
		ID:       "AF-0266",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "journalctl",
		Message:  "Security-relevant executable observed (journalctl)",
	},
	{
		ID:       "AF-0267",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/mount",
		Message:  "Security-relevant executable observed (/usr/bin/mount)",
	},
	{
		ID:       "AF-0268",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "mount",
		Message:  "Security-relevant executable observed (mount)",
	},
	{
		ID:       "AF-0269",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/umount",
		Message:  "Security-relevant executable observed (/usr/bin/umount)",
	},
	{
		ID:       "AF-0270",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "umount",
		Message:  "Security-relevant executable observed (umount)",
	},
	{
		ID:       "AF-0271",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/insmod",
		Message:  "Security-relevant executable observed (/usr/sbin/insmod)",
	},
	{
		ID:       "AF-0272",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "insmod",
		Message:  "Security-relevant executable observed (insmod)",
	},
	{
		ID:       "AF-0273",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/rmmod",
		Message:  "Security-relevant executable observed (/usr/sbin/rmmod)",
	},
	{
		ID:       "AF-0274",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "rmmod",
		Message:  "Security-relevant executable observed (rmmod)",
	},
	{
		ID:       "AF-0275",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/modprobe",
		Message:  "Security-relevant executable observed (/usr/sbin/modprobe)",
	},
	{
		ID:       "AF-0276",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "modprobe",
		Message:  "Security-relevant executable observed (modprobe)",
	},
	{
		ID:       "AF-0277",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/dnf",
		Message:  "Security-relevant executable observed (/usr/bin/dnf)",
	},
	{
		ID:       "AF-0278",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "dnf",
		Message:  "Security-relevant executable observed (dnf)",
	},
	{
		ID:       "AF-0279",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/rpm",
		Message:  "Security-relevant executable observed (/usr/bin/rpm)",
	},
	{
		ID:       "AF-0280",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "rpm",
		Message:  "Security-relevant executable observed (rpm)",
	},
	{
		ID:       "AF-0281",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/curl",
		Message:  "Security-relevant executable observed (/usr/bin/curl)",
	},
	{
		ID:       "AF-0282",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "curl",
		Message:  "Security-relevant executable observed (curl)",
	},
	{
		ID:       "AF-0283",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/wget",
		Message:  "Security-relevant executable observed (/usr/bin/wget)",
	},
	{
		ID:       "AF-0284",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "wget",
		Message:  "Security-relevant executable observed (wget)",
	},
	{
		ID:       "AF-0285",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/ssh",
		Message:  "Security-relevant executable observed (/usr/bin/ssh)",
	},
	{
		ID:       "AF-0286",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "ssh",
		Message:  "Security-relevant executable observed (ssh)",
	},
	{
		ID:       "AF-0287",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/scp",
		Message:  "Security-relevant executable observed (/usr/bin/scp)",
	},
	{
		ID:       "AF-0288",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "scp",
		Message:  "Security-relevant executable observed (scp)",
	},
	{
		ID:       "AF-0289",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/sftp",
		Message:  "Security-relevant executable observed (/usr/bin/sftp)",
	},
	{
		ID:       "AF-0290",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "sftp",
		Message:  "Security-relevant executable observed (sftp)",
	},
	{
		ID:       "AF-0291",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/nc",
		Message:  "Security-relevant executable observed (/usr/bin/nc)",
	},
	{
		ID:       "AF-0292",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "nc",
		Message:  "Security-relevant executable observed (nc)",
	},
	{
		ID:       "AF-0293",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/socat",
		Message:  "Security-relevant executable observed (/usr/bin/socat)",
	},
	{
		ID:       "AF-0294",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "socat",
		Message:  "Security-relevant executable observed (socat)",
	},
	{
		ID:       "AF-0295",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/openssl",
		Message:  "Security-relevant executable observed (/usr/bin/openssl)",
	},
	{
		ID:       "AF-0296",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "openssl",
		Message:  "Security-relevant executable observed (openssl)",
	},
	{
		ID:       "AF-0297",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/gpg",
		Message:  "Security-relevant executable observed (/usr/bin/gpg)",
	},
	{
		ID:       "AF-0298",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "gpg",
		Message:  "Security-relevant executable observed (gpg)",
	},
	{
		ID:       "AF-0299",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/podman",
		Message:  "Security-relevant executable observed (/usr/bin/podman)",
	},
	{
		ID:       "AF-0300",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "podman",
		Message:  "Security-relevant executable observed (podman)",
	},
	{
		ID:       "AF-0301",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/virsh",
		Message:  "Security-relevant executable observed (/usr/bin/virsh)",
	},
	{
		ID:       "AF-0302",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "virsh",
		Message:  "Security-relevant executable observed (virsh)",
	},
	{
		ID:       "AF-0303",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/firewall-cmd",
		Message:  "Security-relevant executable observed (/usr/bin/firewall-cmd)",
	},
	{
		ID:       "AF-0304",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "firewall-cmd",
		Message:  "Security-relevant executable observed (firewall-cmd)",
	},
	{
		ID:       "AF-0305",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/iptables",
		Message:  "Security-relevant executable observed (/usr/sbin/iptables)",
	},
	{
		ID:       "AF-0306",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "iptables",
		Message:  "Security-relevant executable observed (iptables)",
	},
	{
		ID:       "AF-0307",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/nft",
		Message:  "Security-relevant executable observed (/usr/sbin/nft)",
	},
	{
		ID:       "AF-0308",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "nft",
		Message:  "Security-relevant executable observed (nft)",
	},
	{
		ID:       "AF-0309",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/crontab",
		Message:  "Security-relevant executable observed (/usr/bin/crontab)",
	},
	{
		ID:       "AF-0310",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "crontab",
		Message:  "Security-relevant executable observed (crontab)",
	},
	{
		ID:       "AF-0311",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/at",
		Message:  "Security-relevant executable observed (/usr/bin/at)",
	},
	{
		ID:       "AF-0312",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "at",
		Message:  "Security-relevant executable observed (at)",
	},
	{
		ID:       "AF-0313",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/bash",
		Message:  "Security-relevant executable observed (/usr/bin/bash)",
	},
	{
		ID:       "AF-0314",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "bash",
		Message:  "Security-relevant executable observed (bash)",
	},
	{
		ID:       "AF-0315",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/sh",
		Message:  "Security-relevant executable observed (/usr/bin/sh)",
	},
	{
		ID:       "AF-0316",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "sh",
		Message:  "Security-relevant executable observed (sh)",
	},
	{
		ID:       "AF-0317",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/python3",
		Message:  "Security-relevant executable observed (/usr/bin/python3)",
	},
	{
		ID:       "AF-0318",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "python3",
		Message:  "Security-relevant executable observed (python3)",
	},
	{
		ID:       "AF-0319",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/perl",
		Message:  "Security-relevant executable observed (/usr/bin/perl)",
	},
	{
		ID:       "AF-0320",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "perl",
		Message:  "Security-relevant executable observed (perl)",
	},
	{
		ID:       "AF-0321",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/php",
		Message:  "Security-relevant executable observed (/usr/bin/php)",
	},
	{
		ID:       "AF-0322",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "php",
		Message:  "Security-relevant executable observed (php)",
	},
	{
		ID:       "AF-0323",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/node",
		Message:  "Security-relevant executable observed (/usr/bin/node)",
	},
	{
		ID:       "AF-0324",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "node",
		Message:  "Security-relevant executable observed (node)",
	},
	{
		ID:       "AF-0325",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/go",
		Message:  "Security-relevant executable observed (/usr/bin/go)",
	},
	{
		ID:       "AF-0326",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "go",
		Message:  "Security-relevant executable observed (go)",
	},
	{
		ID:       "AF-0327",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/gcc",
		Message:  "Security-relevant executable observed (/usr/bin/gcc)",
	},
	{
		ID:       "AF-0328",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "gcc",
		Message:  "Security-relevant executable observed (gcc)",
	},
	{
		ID:       "AF-0329",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/ld",
		Message:  "Security-relevant executable observed (/usr/bin/ld)",
	},
	{
		ID:       "AF-0330",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "ld",
		Message:  "Security-relevant executable observed (ld)",
	},
	{
		ID:       "AF-0331",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/strace",
		Message:  "Security-relevant executable observed (/usr/bin/strace)",
	},
	{
		ID:       "AF-0332",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "strace",
		Message:  "Security-relevant executable observed (strace)",
	},
	{
		ID:       "AF-0333",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/gdb",
		Message:  "Security-relevant executable observed (/usr/bin/gdb)",
	},
	{
		ID:       "AF-0334",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "gdb",
		Message:  "Security-relevant executable observed (gdb)",
	},
	{
		ID:       "AF-0335",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/tcpdump",
		Message:  "Security-relevant executable observed (/usr/bin/tcpdump)",
	},
	{
		ID:       "AF-0336",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "tcpdump",
		Message:  "Security-relevant executable observed (tcpdump)",
	},
	{
		ID:       "AF-0337",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/tuned-adm",
		Message:  "Security-relevant executable observed (/usr/sbin/tuned-adm)",
	},
	{
		ID:       "AF-0338",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "tuned-adm",
		Message:  "Security-relevant executable observed (tuned-adm)",
	},
	{
		ID:       "AF-0339",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/sbin/sysctl",
		Message:  "Security-relevant executable observed (/usr/sbin/sysctl)",
	},
	{
		ID:       "AF-0340",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "sysctl",
		Message:  "Security-relevant executable observed (sysctl)",
	},
	{
		ID:       "AF-0341",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/nsenter",
		Message:  "Security-relevant executable observed (/usr/bin/nsenter)",
	},
	{
		ID:       "AF-0342",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "nsenter",
		Message:  "Security-relevant executable observed (nsenter)",
	},
	{
		ID:       "AF-0343",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/unshare",
		Message:  "Security-relevant executable observed (/usr/bin/unshare)",
	},
	{
		ID:       "AF-0344",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "unshare",
		Message:  "Security-relevant executable observed (unshare)",
	},
	{
		ID:       "AF-0345",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/setpriv",
		Message:  "Security-relevant executable observed (/usr/bin/setpriv)",
	},
	{
		ID:       "AF-0346",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "setpriv",
		Message:  "Security-relevant executable observed (setpriv)",
	},
	{
		ID:       "AF-0347",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/chroot",
		Message:  "Security-relevant executable observed (/usr/bin/chroot)",
	},
	{
		ID:       "AF-0348",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "chroot",
		Message:  "Security-relevant executable observed (chroot)",
	},
	{
		ID:       "AF-0349",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/kill",
		Message:  "Security-relevant executable observed (/usr/bin/kill)",
	},
	{
		ID:       "AF-0350",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "kill",
		Message:  "Security-relevant executable observed (kill)",
	},
	{
		ID:       "AF-0351",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/pkill",
		Message:  "Security-relevant executable observed (/usr/bin/pkill)",
	},
	{
		ID:       "AF-0352",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "pkill",
		Message:  "Security-relevant executable observed (pkill)",
	},
	{
		ID:       "AF-0353",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/truncate",
		Message:  "Security-relevant executable observed (/usr/bin/truncate)",
	},
	{
		ID:       "AF-0354",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "truncate",
		Message:  "Security-relevant executable observed (truncate)",
	},
	{
		ID:       "AF-0355",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/shred",
		Message:  "Security-relevant executable observed (/usr/bin/shred)",
	},
	{
		ID:       "AF-0356",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "shred",
		Message:  "Security-relevant executable observed (shred)",
	},
	{
		ID:       "AF-0357",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "exe",
		Operator: "equals",
		Value:    "/usr/bin/dd",
		Message:  "Security-relevant executable observed (/usr/bin/dd)",
	},
	{
		ID:       "AF-0358",
		Category: "sensitive-execution",
		Severity: "medium",
		Type:     "SYSCALL",
		Field:    "comm",
		Operator: "equals",
		Value:    "dd",
		Message:  "Security-relevant executable observed (dd)",
	},
	{
		ID:       "AF-0359",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/passwd",
		Message:  "Sensitive path access requires review (/etc/passwd)",
	},
	{
		ID:       "AF-0360",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/shadow",
		Message:  "Sensitive path access requires review (/etc/shadow)",
	},
	{
		ID:       "AF-0361",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/group",
		Message:  "Sensitive path access requires review (/etc/group)",
	},
	{
		ID:       "AF-0362",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/gshadow",
		Message:  "Sensitive path access requires review (/etc/gshadow)",
	},
	{
		ID:       "AF-0363",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/sudoers",
		Message:  "Sensitive path access requires review (/etc/sudoers)",
	},
	{
		ID:       "AF-0364",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/sudoers.d",
		Message:  "Sensitive path access requires review (/etc/sudoers.d)",
	},
	{
		ID:       "AF-0365",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/ssh/sshd_config",
		Message:  "Sensitive path access requires review (/etc/ssh/sshd_config)",
	},
	{
		ID:       "AF-0366",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/ssh/ssh_config",
		Message:  "Sensitive path access requires review (/etc/ssh/ssh_config)",
	},
	{
		ID:       "AF-0367",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/selinux/config",
		Message:  "Sensitive path access requires review (/etc/selinux/config)",
	},
	{
		ID:       "AF-0368",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/audit/auditd.conf",
		Message:  "Sensitive path access requires review (/etc/audit/auditd.conf)",
	},
	{
		ID:       "AF-0369",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/audit/rules.d",
		Message:  "Sensitive path access requires review (/etc/audit/rules.d)",
	},
	{
		ID:       "AF-0370",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/systemd/system",
		Message:  "Sensitive path access requires review (/etc/systemd/system)",
	},
	{
		ID:       "AF-0371",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/usr/lib/systemd/system",
		Message:  "Sensitive path access requires review (/usr/lib/systemd/system)",
	},
	{
		ID:       "AF-0372",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/boot",
		Message:  "Sensitive path access requires review (/boot)",
	},
	{
		ID:       "AF-0373",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/boot/loader",
		Message:  "Sensitive path access requires review (/boot/loader)",
	},
	{
		ID:       "AF-0374",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/default/grub",
		Message:  "Sensitive path access requires review (/etc/default/grub)",
	},
	{
		ID:       "AF-0375",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/grub2.cfg",
		Message:  "Sensitive path access requires review (/etc/grub2.cfg)",
	},
	{
		ID:       "AF-0376",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/cron.d",
		Message:  "Sensitive path access requires review (/etc/cron.d)",
	},
	{
		ID:       "AF-0377",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/crontab",
		Message:  "Sensitive path access requires review (/etc/crontab)",
	},
	{
		ID:       "AF-0378",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/var/spool/cron",
		Message:  "Sensitive path access requires review (/var/spool/cron)",
	},
	{
		ID:       "AF-0379",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/pam.d",
		Message:  "Sensitive path access requires review (/etc/pam.d)",
	},
	{
		ID:       "AF-0380",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/security",
		Message:  "Sensitive path access requires review (/etc/security)",
	},
	{
		ID:       "AF-0381",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/hosts",
		Message:  "Sensitive path access requires review (/etc/hosts)",
	},
	{
		ID:       "AF-0382",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/resolv.conf",
		Message:  "Sensitive path access requires review (/etc/resolv.conf)",
	},
	{
		ID:       "AF-0383",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/nsswitch.conf",
		Message:  "Sensitive path access requires review (/etc/nsswitch.conf)",
	},
	{
		ID:       "AF-0384",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/ld.so.preload",
		Message:  "Sensitive path access requires review (/etc/ld.so.preload)",
	},
	{
		ID:       "AF-0385",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/ld.so.conf",
		Message:  "Sensitive path access requires review (/etc/ld.so.conf)",
	},
	{
		ID:       "AF-0386",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/modprobe.d",
		Message:  "Sensitive path access requires review (/etc/modprobe.d)",
	},
	{
		ID:       "AF-0387",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/modules-load.d",
		Message:  "Sensitive path access requires review (/etc/modules-load.d)",
	},
	{
		ID:       "AF-0388",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/sysctl.conf",
		Message:  "Sensitive path access requires review (/etc/sysctl.conf)",
	},
	{
		ID:       "AF-0389",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/sysctl.d",
		Message:  "Sensitive path access requires review (/etc/sysctl.d)",
	},
	{
		ID:       "AF-0390",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/firewalld",
		Message:  "Sensitive path access requires review (/etc/firewalld)",
	},
	{
		ID:       "AF-0391",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/NetworkManager",
		Message:  "Sensitive path access requires review (/etc/NetworkManager)",
	},
	{
		ID:       "AF-0392",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/containers",
		Message:  "Sensitive path access requires review (/etc/containers)",
	},
	{
		ID:       "AF-0393",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/pki",
		Message:  "Sensitive path access requires review (/etc/pki)",
	},
	{
		ID:       "AF-0394",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/ssl",
		Message:  "Sensitive path access requires review (/etc/ssl)",
	},
	{
		ID:       "AF-0395",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/root/.ssh",
		Message:  "Sensitive path access requires review (/root/.ssh)",
	},
	{
		ID:       "AF-0396",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/.ssh/authorized_keys",
		Message:  "Sensitive path access requires review (/.ssh/authorized_keys)",
	},
	{
		ID:       "AF-0397",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/fstab",
		Message:  "Sensitive path access requires review (/etc/fstab)",
	},
	{
		ID:       "AF-0398",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/crypttab",
		Message:  "Sensitive path access requires review (/etc/crypttab)",
	},
	{
		ID:       "AF-0399",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/lvm",
		Message:  "Sensitive path access requires review (/etc/lvm)",
	},
	{
		ID:       "AF-0400",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/var/lib/rpm",
		Message:  "Sensitive path access requires review (/var/lib/rpm)",
	},
	{
		ID:       "AF-0401",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/var/lib/dnf",
		Message:  "Sensitive path access requires review (/var/lib/dnf)",
	},
	{
		ID:       "AF-0402",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/yum.repos.d",
		Message:  "Sensitive path access requires review (/etc/yum.repos.d)",
	},
	{
		ID:       "AF-0403",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/profile",
		Message:  "Sensitive path access requires review (/etc/profile)",
	},
	{
		ID:       "AF-0404",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/profile.d",
		Message:  "Sensitive path access requires review (/etc/profile.d)",
	},
	{
		ID:       "AF-0405",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/bashrc",
		Message:  "Sensitive path access requires review (/etc/bashrc)",
	},
	{
		ID:       "AF-0406",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/environment",
		Message:  "Sensitive path access requires review (/etc/environment)",
	},
	{
		ID:       "AF-0407",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/login.defs",
		Message:  "Sensitive path access requires review (/etc/login.defs)",
	},
	{
		ID:       "AF-0408",
		Category: "sensitive-path",
		Severity: "high",
		Type:     "PATH",
		Field:    "name",
		Operator: "contains",
		Value:    "/etc/securetty",
		Message:  "Sensitive path access requires review (/etc/securetty)",
	},
}

func parseFields(s string) map[string]string {
	out := make(map[string]string)
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			continue
		}
		key := s[start:i]
		i++
		if key == "" {
			continue
		}
		var value string
		if i < len(s) && (s[i] == '"' || s[i] == '\'') {
			quote := s[i]
			i++
			start = i
			var b strings.Builder
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					i++
					b.WriteByte(s[i])
					i++
					continue
				}
				if s[i] == quote {
					break
				}
				b.WriteByte(s[i])
				i++
			}
			value = b.String()
			if i < len(s) {
				i++
			}
			_ = start
		} else {
			start = i
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			value = s[start:i]
		}
		out[key] = value
	}
	return out
}
func parseRecord(line, source string, number int, raw bool) (Record, error) {
	r := Record{Fields: parseFields(line), Source: source, Line: number}
	if raw {
		r.Raw = line
	}
	m := typeRE.FindStringSubmatch(line)
	if len(m) < 2 {
		return r, errors.New("missing audit type")
	}
	r.Type = m[1]
	if r.Type == "AVC" && strings.Contains(strings.ToLower(line), "denied") {
		r.Fields["avc"] = "denied"
	}
	n := nodeRE.FindStringSubmatch(line)
	if len(n) > 1 {
		r.Node = n[1]
	}
	m = messageRE.FindStringSubmatch(line)
	if len(m) < 4 {
		return r, errors.New("missing audit timestamp or serial")
	}
	sec, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return r, err
	}
	frac := m[2]
	for len(frac) < 9 {
		frac += "0"
	}
	if len(frac) > 9 {
		frac = frac[:9]
	}
	nano, _ := strconv.ParseInt(frac, 10, 64)
	r.Timestamp = time.Unix(sec, nano).UTC()
	r.Serial = m[3]
	return r, nil
}
func unique(items []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(items))
	for _, v := range items {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
func decodeHex(v string) string {
	if len(v)%2 != 0 || !hexRE.MatchString(v) {
		return v
	}
	b := make([]byte, len(v)/2)
	for i := 0; i < len(b); i++ {
		n, e := strconv.ParseUint(v[2*i:2*i+2], 16, 8)
		if e != nil {
			return v
		}
		b[i] = byte(n)
	}
	for _, c := range b {
		if c < 32 && c != 9 {
			return v
		}
	}
	return string(b)
}
func eventKey(r Record) string {
	return r.Node + "/" + r.Serial + "/" + strconv.FormatInt(r.Timestamp.Unix(), 10)
}
func buildEvents(records []Record, limit int) []Event {
	index := make(map[string]int)
	events := make([]Event, 0)
	for _, r := range records {
		k := eventKey(r)
		idx, ok := index[k]
		if !ok {
			if limit > 0 && len(events) >= limit {
				continue
			}
			idx = len(events)
			index[k] = idx
			events = append(events, Event{ID: k, Timestamp: r.Timestamp, Node: r.Node})
		}
		e := &events[idx]
		e.Records = append(e.Records, r)
		e.Types = append(e.Types, r.Type)
		f := r.Fields
		for _, key := range []string{"subj", "scontext", "tcontext"} {
			if v := f[key]; v != "" {
				e.Subjects = append(e.Subjects, v)
			}
		}
		for _, key := range []string{"exe", "comm"} {
			if v := f[key]; v != "" {
				e.Executables = append(e.Executables, decodeHex(v))
			}
		}
		for _, key := range []string{"name", "path", "cwd"} {
			if v := f[key]; v != "" {
				e.Paths = append(e.Paths, decodeHex(v))
			}
		}
		for _, key := range []string{"uid", "auid", "acct"} {
			if v := f[key]; v != "" {
				e.Users = append(e.Users, v)
			}
		}
	}
	for i := range events {
		e := &events[i]
		e.Types = unique(e.Types)
		e.Subjects = unique(e.Subjects)
		e.Executables = unique(e.Executables)
		e.Paths = unique(e.Paths)
		e.Users = unique(e.Users)
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })
	return events
}
func matchRule(r Record, rule Rule) bool {
	if r.Type == "AVC" && rule.Field == "avc" {
		return strings.Contains(strings.ToLower(r.Raw), "denied") || strings.Contains(strings.ToLower(r.Fields["msg"]), "denied")
	}
	if r.Type != rule.Type {
		return false
	}
	v, ok := r.Fields[rule.Field]
	if !ok {
		return false
	}
	v = decodeHex(v)
	switch rule.Operator {
	case "exists":
		return v != ""
	case "equals":
		return strings.EqualFold(v, rule.Value)
	case "contains":
		return strings.Contains(strings.ToLower(v), strings.ToLower(rule.Value))
	case "prefix":
		return strings.HasPrefix(v, rule.Value)
	case "suffix":
		return strings.HasSuffix(v, rule.Value)
	}
	return false
}
func rank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}
func analyze(events []Event, category, severity string) []Finding {
	byType := make(map[string][]Rule)
	for _, rule := range auditRules {
		byType[rule.Type] = append(byType[rule.Type], rule)
	}
	findings := make([]Finding, 0)
	for ei := range events {
		e := &events[ei]
		e.Severity = "info"
		tags := make([]string, 0)
		for _, r := range e.Records {
			for _, rule := range byType[r.Type] {
				if category != "" && !strings.EqualFold(category, rule.Category) {
					continue
				}
				if severity != "" && rank(rule.Severity) < rank(severity) {
					continue
				}
				if !matchRule(r, rule) {
					continue
				}
				f := Finding{Rule: rule.ID, Severity: rule.Severity, Category: rule.Category, Message: rule.Message, EventID: e.ID, Timestamp: e.Timestamp, Evidence: map[string]string{"type": r.Type, rule.Field: r.Fields[rule.Field], "source": r.Source, "line": strconv.Itoa(r.Line)}}
				findings = append(findings, f)
				e.Findings = append(e.Findings, f)
				tags = append(tags, rule.Category)
				if rank(rule.Severity) > rank(e.Severity) {
					e.Severity = rule.Severity
				}
			}
		}
		e.Tags = unique(tags)
	}
	return findings
}
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(v, 0).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid timestamp %q", s)
}
func openInput(path string) (io.ReadCloser, error) {
	if path == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		z, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &compoundCloser{Reader: z, closers: []io.Closer{z, f}}, nil
	}
	return f, nil
}

type compoundCloser struct {
	io.Reader
	closers []io.Closer
}

func (c *compoundCloser) Close() error {
	var first error
	for _, v := range c.closers {
		if err := v.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
func resolveInputs(spec string) ([]string, error) {
	if strings.TrimSpace(spec) == "" {
		spec = "/var/log/audit/audit.log"
	}
	out := make([]string, 0)
	seen := make(map[string]bool)
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		candidates := []string{part}
		if strings.ContainsAny(part, "*?[") {
			matches, err := filepath.Glob(part)
			if err != nil {
				return nil, err
			}
			candidates = matches
		}
		for _, c := range candidates {
			if c != "-" {
				info, err := os.Stat(c)
				if err != nil {
					return nil, err
				}
				if info.IsDir() {
					entries, err := os.ReadDir(c)
					if err != nil {
						return nil, err
					}
					for _, entry := range entries {
						if !entry.IsDir() && (strings.Contains(entry.Name(), "audit.log") || strings.HasSuffix(entry.Name(), ".gz")) {
							candidate := filepath.Join(c, entry.Name())
							if !seen[candidate] {
								out = append(out, candidate)
								seen[candidate] = true
							}
						}
					}
					continue
				}
			}
			if !seen[c] {
				out = append(out, c)
				seen[c] = true
			}
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, errors.New("no audit inputs found")
	}
	return out, nil
}
func readRecords(inputs []string, opt Options) ([]Record, int, []string, error) {
	since, err := parseTime(opt.Since)
	if err != nil {
		return nil, 0, nil, err
	}
	until, err := parseTime(opt.Until)
	if err != nil {
		return nil, 0, nil, err
	}
	allowed := make(map[string]bool)
	for _, t := range strings.Split(opt.Types, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			allowed[strings.ToUpper(t)] = true
		}
	}
	records := make([]Record, 0)
	bad := 0
	warnings := make([]string, 0)
	for _, path := range inputs {
		reader, err := openInput(path)
		if err != nil {
			if opt.Strict {
				return nil, bad, warnings, err
			}
			warnings = append(warnings, err.Error())
			continue
		}
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 64*1024), opt.MaxLine)
		line := 0
		for scanner.Scan() {
			line++
			raw := scanner.Text()
			r, e := parseRecord(raw, path, line, opt.IncludeRaw)
			if e != nil {
				bad++
				if opt.Strict {
					reader.Close()
					return nil, bad, warnings, fmt.Errorf("%s:%d: %w", path, line, e)
				}
				continue
			}
			if !since.IsZero() && r.Timestamp.Before(since) {
				continue
			}
			if !until.IsZero() && r.Timestamp.After(until) {
				continue
			}
			if len(allowed) > 0 && !allowed[strings.ToUpper(r.Type)] {
				continue
			}
			if opt.Node != "" && !strings.EqualFold(r.Node, opt.Node) {
				continue
			}
			if opt.Search != "" && !strings.Contains(strings.ToLower(raw), strings.ToLower(opt.Search)) {
				continue
			}
			if opt.User != "" && r.Fields["uid"] != opt.User && r.Fields["auid"] != opt.User && r.Fields["acct"] != opt.User {
				continue
			}
			if opt.Executable != "" && !strings.Contains(strings.ToLower(r.Fields["exe"]+" "+r.Fields["comm"]), strings.ToLower(opt.Executable)) {
				continue
			}
			records = append(records, r)
		}
		if err := scanner.Err(); err != nil {
			if opt.Strict {
				reader.Close()
				return nil, bad, warnings, err
			}
			warnings = append(warnings, fmt.Sprintf("%s: %v", path, err))
		}
		reader.Close()
	}
	return records, bad, warnings, nil
}
func hostname() string {
	v, e := os.Hostname()
	if e != nil {
		return "unknown"
	}
	return v
}
func reportFrom(records []Record, events []Event, findings []Finding, inputs []string, bad int, warnings []string, opt Options) Report {
	report := Report{Generated: time.Now().UTC(), Host: hostname(), Inputs: inputs, Records: len(records), Events: len(events), ParseErrors: bad, TypeCounts: make(map[string]int), SeverityCounts: make(map[string]int), CategoryCounts: make(map[string]int), Findings: findings, Warnings: warnings}
	for _, r := range records {
		report.TypeCounts[r.Type]++
	}
	for _, f := range findings {
		report.SeverityCounts[f.Severity]++
		report.CategoryCounts[f.Category]++
	}
	if opt.IncludeEvents {
		report.EventDetails = events
	}
	return report
}
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
func writeNDJSON(w io.Writer, report Report) error {
	enc := json.NewEncoder(w)
	for _, f := range report.Findings {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}
func writeCSV(w io.Writer, report Report) error {
	c := csv.NewWriter(w)
	if err := c.Write([]string{"timestamp", "event_id", "rule", "severity", "category", "message", "evidence"}); err != nil {
		return err
	}
	for _, f := range report.Findings {
		e, _ := json.Marshal(f.Evidence)
		if err := c.Write([]string{f.Timestamp.Format(time.RFC3339Nano), f.EventID, f.Rule, f.Severity, f.Category, f.Message, string(e)}); err != nil {
			return err
		}
	}
	c.Flush()
	return c.Error()
}
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}
func writeText(w io.Writer, r Report, limit int, summary bool) error {
	fmt.Fprintf(w, "AUDIT FORENSICS\nHost: %s\nGenerated: %s\nInputs: %s\nRecords: %d\nEvents: %d\nFindings: %d\nParse errors: %d\n", r.Host, r.Generated.Format(time.RFC3339), strings.Join(r.Inputs, ", "), r.Records, r.Events, len(r.Findings), r.ParseErrors)
	fmt.Fprintln(w, "\nSeverity distribution:")
	for _, k := range sortedKeys(r.SeverityCounts) {
		fmt.Fprintf(w, "  %-12s %d\n", k, r.SeverityCounts[k])
	}
	fmt.Fprintln(w, "\nAudit record types:")
	for _, k := range sortedKeys(r.TypeCounts) {
		fmt.Fprintf(w, "  %-25s %d\n", k, r.TypeCounts[k])
	}
	fmt.Fprintln(w, "\nFinding categories:")
	for _, k := range sortedKeys(r.CategoryCounts) {
		fmt.Fprintf(w, "  %-25s %d\n", k, r.CategoryCounts[k])
	}
	for _, warning := range r.Warnings {
		fmt.Fprintf(w, "Warning: %s\n", warning)
	}
	if summary {
		return nil
	}
	fmt.Fprintln(w, "\nFindings:")
	count := len(r.Findings)
	if limit > 0 && limit < count {
		count = limit
	}
	for i := 0; i < count; i++ {
		f := r.Findings[i]
		fmt.Fprintf(w, "%s %-8s %-9s %-22s %s [%s]\n", f.Timestamp.Format("2006-01-02 15:04:05"), strings.ToUpper(f.Severity), f.Rule, f.Category, f.Message, f.EventID)
	}
	if count < len(r.Findings) {
		fmt.Fprintf(w, "... %d additional findings omitted\n", len(r.Findings)-count)
	}
	return nil
}
func writeReport(w io.Writer, report Report, opt Options) error {
	switch strings.ToLower(opt.Format) {
	case "json":
		return writeJSON(w, report)
	case "ndjson":
		return writeNDJSON(w, report)
	case "csv":
		return writeCSV(w, report)
	case "text", "":
		return writeText(w, report, opt.Limit, opt.Summary)
	default:
		return fmt.Errorf("unsupported format %q", opt.Format)
	}
}
func saveReport(path string, report Report, opt Options) error {
	if path == "" || path == "-" {
		return writeReport(os.Stdout, report, opt)
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".audit-forensics-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err := writeReport(f, report, opt); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

type Baseline struct {
	Created        time.Time      `json:"created"`
	Host           string         `json:"host"`
	Records        int            `json:"records"`
	Events         int            `json:"events"`
	TypeCounts     map[string]int `json:"type_counts"`
	SeverityCounts map[string]int `json:"severity_counts"`
	CategoryCounts map[string]int `json:"category_counts"`
	FindingHashes  map[string]int `json:"finding_hashes"`
}

func hashFinding(f Finding) string {
	h := sha256.Sum256([]byte(f.Rule + "|" + f.Category + "|" + f.Message + "|" + f.Evidence["type"]))
	return fmt.Sprintf("%x", h[:])
}
func baselineFrom(r Report) Baseline {
	b := Baseline{Created: time.Now().UTC(), Host: r.Host, Records: r.Records, Events: r.Events, TypeCounts: r.TypeCounts, SeverityCounts: r.SeverityCounts, CategoryCounts: r.CategoryCounts, FindingHashes: make(map[string]int)}
	for _, f := range r.Findings {
		b.FindingHashes[hashFinding(f)]++
	}
	return b
}
func loadBaseline(path string) (Baseline, error) {
	var b Baseline
	data, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	err = json.Unmarshal(data, &b)
	return b, err
}
func compareBaseline(w io.Writer, r Report, path string) error {
	b, err := loadBaseline(path)
	if err != nil {
		return err
	}
	current := baselineFrom(r)
	fmt.Fprintf(w, "Baseline comparison\nBaseline host: %s\nCurrent host: %s\nRecords: %+d\nEvents: %+d\n", b.Host, r.Host, r.Records-b.Records, r.Events-b.Events)
	keys := make(map[string]bool)
	for k := range b.TypeCounts {
		keys[k] = true
	}
	for k := range r.TypeCounts {
		keys[k] = true
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		delta := r.TypeCounts[k] - b.TypeCounts[k]
		if delta != 0 {
			fmt.Fprintf(w, "Type %-25s %+d\n", k, delta)
		}
	}
	novel := 0
	for k, n := range current.FindingHashes {
		if b.FindingHashes[k] == 0 {
			novel += n
		}
	}
	fmt.Fprintf(w, "Findings with previously unseen signatures: %d\n", novel)
	return nil
}
func collectJournal() ([]byte, error) {
	cmd := exec.Command("journalctl", "--no-pager", "-o", "cat", "-t", "audit")
	return cmd.Output()
}
func options() Options {
	var o Options
	flag.StringVar(&o.Inputs, "input", "/var/log/audit/audit.log", "Comma-separated audit logs, directories, globs, gzip files, or -")
	flag.StringVar(&o.Format, "format", "text", "Output: text, json, csv, ndjson")
	flag.StringVar(&o.Output, "output", "-", "Output filename or - for stdout")
	flag.StringVar(&o.Since, "since", "", "Start time, RFC3339, date, or Unix epoch")
	flag.StringVar(&o.Until, "until", "", "End time, RFC3339, date, or Unix epoch")
	flag.StringVar(&o.Types, "types", "", "Comma-separated audit record types")
	flag.StringVar(&o.Category, "category", "", "Restrict findings to a rule category")
	flag.StringVar(&o.Severity, "severity", "", "Minimum finding severity: info, low, medium, high, critical")
	flag.StringVar(&o.Search, "search", "", "Case-insensitive substring filter on raw records")
	flag.StringVar(&o.User, "user", "", "Filter by uid, auid, or acct")
	flag.StringVar(&o.Executable, "executable", "", "Filter by exe or comm")
	flag.StringVar(&o.Node, "node", "", "Filter by audit node")
	flag.IntVar(&o.Limit, "limit", 100, "Maximum findings shown in text output, 0 for all")
	flag.IntVar(&o.MaxLine, "max-line", 4*1024*1024, "Maximum audit log line length")
	flag.IntVar(&o.MaxEvents, "max-events", 0, "Maximum correlated events, 0 for unlimited")
	flag.BoolVar(&o.IncludeEvents, "events", false, "Include correlated events in JSON")
	flag.BoolVar(&o.IncludeRaw, "raw", false, "Include original record text in events")
	flag.BoolVar(&o.Strict, "strict", false, "Stop on malformed records")
	flag.BoolVar(&o.Quiet, "quiet", false, "Suppress nonfatal diagnostics")
	flag.StringVar(&o.Sort, "sort", "time", "Finding order: time, severity, category, rule")
	flag.StringVar(&o.Baseline, "baseline", "", "Compare report with saved baseline")
	flag.StringVar(&o.SaveBaseline, "save-baseline", "", "Write baseline JSON")
	flag.BoolVar(&o.ListRules, "list-rules", false, "Print built-in detection rules")
	flag.BoolVar(&o.ListTypes, "list-types", false, "Print supported audit record types")
	flag.BoolVar(&o.Summary, "summary", false, "Show summary only in text mode")
	flag.BoolVar(&o.Journal, "journal", false, "Read audit-tagged journal records instead of input files")
	flag.Parse()
	return o
}
func run(opt Options) error {
	if opt.ListRules {
		for _, r := range auditRules {
			fmt.Printf("%-9s %-22s %-9s %-23s %-10s %-8s %s\n", r.ID, r.Category, r.Severity, r.Type, r.Field, r.Operator, r.Value)
		}
		return nil
	}
	if opt.ListTypes {
		seen := make(map[string]bool)
		for _, r := range auditRules {
			seen[r.Type] = true
		}
		keys := make([]string, 0, len(seen))
		for k := range seen {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Println(k)
		}
		return nil
	}
	var inputs []string
	var records []Record
	var bad int
	var warnings []string
	var err error
	if opt.Journal {
		var data []byte
		data, err = collectJournal()
		if err != nil {
			return fmt.Errorf("journal audit extraction failed: %w", err)
		}
		inputs = []string{"journalctl -t audit"}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		scanner.Buffer(make([]byte, 64*1024), opt.MaxLine)
		n := 0
		for scanner.Scan() {
			n++
			r, e := parseRecord(scanner.Text(), inputs[0], n, opt.IncludeRaw)
			if e != nil {
				bad++
				continue
			}
			records = append(records, r)
		}
		if err = scanner.Err(); err != nil {
			return err
		}
	} else {
		inputs, err = resolveInputs(opt.Inputs)
		if err != nil {
			return err
		}
		records, bad, warnings, err = readRecords(inputs, opt)
		if err != nil {
			return err
		}
	}
	events := buildEvents(records, opt.MaxEvents)
	findings := analyze(events, opt.Category, opt.Severity)
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		switch opt.Sort {
		case "severity":
			if rank(a.Severity) != rank(b.Severity) {
				return rank(a.Severity) > rank(b.Severity)
			}
		case "category":
			if a.Category != b.Category {
				return a.Category < b.Category
			}
		case "rule":
			if a.Rule != b.Rule {
				return a.Rule < b.Rule
			}
		}
		return a.Timestamp.Before(b.Timestamp)
	})
	report := reportFrom(records, events, findings, inputs, bad, warnings, opt)
	if opt.SaveBaseline != "" {
		b := baselineFrom(report)
		data, e := json.MarshalIndent(b, "", "  ")
		if e != nil {
			return e
		}
		if e = os.WriteFile(opt.SaveBaseline, append(data, '\n'), 0600); e != nil {
			return e
		}
	}
	if err = saveReport(opt.Output, report, opt); err != nil {
		return err
	}
	if opt.Baseline != "" {
		return compareBaseline(os.Stderr, report, opt.Baseline)
	}
	return nil
}
func main() {
	opt := options()
	if err := run(opt); err != nil {
		fmt.Fprintln(os.Stderr, "audit-forensics:", err)
		os.Exit(1)
	}
}
