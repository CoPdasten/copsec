package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Cyberpunk / Matrix Palette
var (
	colorNeonGreen   = lipgloss.Color("#00FF66")
	colorCyberCyan   = lipgloss.Color("#00F0FF")
	colorAlertPink   = lipgloss.Color("#FF0055")
	colorWarningGold = lipgloss.Color("#FFB800")
	colorDarkBg      = lipgloss.Color("#0A0E14")
	colorPanelBorder = lipgloss.Color("#1E293B")
	colorScrollTrack = lipgloss.Color("#24283B")
	colorTextMuted   = lipgloss.Color("#64748B")
	colorTextLight   = lipgloss.Color("#E2E8F0")
	colorSelectedBg  = lipgloss.Color("#1A2333")

	// Pre-cached Styles
	styleBasePanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#334155")).
			Padding(0, 1)

	styleActivePanel = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorCyberCyan).
				Padding(0, 1)

	styleActiveFocusPanel = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#00F0FF")).
				Padding(0, 1)

	styleInactivePanel = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#334155")).
				Padding(0, 1)

	styleHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorCyberCyan)

	styleMatrixTitle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorNeonGreen)

	styleAlert = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAlertPink)

	styleWarning = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWarningGold)

	styleMuted = lipgloss.NewStyle().
			Foreground(colorTextMuted)

	styleLight = lipgloss.NewStyle().
			Foreground(colorTextLight)

	styleCyan = lipgloss.NewStyle().
			Foreground(colorCyberCyan)

	styleGreen = lipgloss.NewStyle().
			Foreground(colorNeonGreen)

	styleScrollTrack = lipgloss.NewStyle().
				Foreground(colorScrollTrack)

	styleSelected = lipgloss.NewStyle().
			Background(colorSelectedBg)

	styleModalBox = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(colorAlertPink).
			Background(lipgloss.Color("#0D1117")).
			Padding(1, 2).
			Width(68)

	styleSearchBox = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(colorCyberCyan).
			Background(lipgloss.Color("#0D1117")).
			Padding(1, 2).
			Width(72)

	styleInspectionCard = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorCyberCyan).
				Background(lipgloss.Color("#0D1117")).
				Padding(1, 2).
				Width(74)
)

type tickMsg time.Time

type modalMode int

const (
	modalNone modalMode = iota
	modalBanIP
	modalUnbanIP
	modalSearch
	modalLogDetail
)

// FocusPanel represents which panel currently holds user keyboard focus.
type FocusPanel int

const (
	FocusTree FocusPanel = iota // 0: Sol Ağaç
	FocusLogs                   // 1: Orta Log Akışı
)

// LogTab represents the active stream filter tab.
type LogTab int

const (
	TabIncidents   LogTab = iota // 0: Sadece Kural İhlalleri & Banlar
	TabAll                       // 1: Tüm Canlı Akış
	TabNginx                     // 2: Web İstekleri
	TabAuth                      // 3: SSH & Sudo & Auth
	TabSuricata                  // 4: IDS / IPS Uyarıları
	TabAuditSyslog               // 5: Audit & Kernel
)

// TreeNodeType defines whether a tree item is a Host or a Sensor.
type TreeNodeType int

const (
	NodeHost TreeNodeType = iota
	NodeSensor
)

// FleetTreeNode represents a hierarchical item in the VS Code style explorer tree.
type FleetTreeNode struct {
	ID         string
	Label      string
	Type       TreeNodeType
	ParentHost string
	SensorKey  string
	Expanded   bool
	Children   []*FleetTreeNode
}

type techniqueStat struct {
	ID     string
	Name   string
	Tactic string
	Count  int
}

type attackerIntel struct {
	IP        string
	Flag      string
	Org       string
	Class     string
	Count     int
	TopTarget string
}

// SIEMModel holds state for the strictly bounded 6-panel SOC cockpit.
type SIEMModel struct {
	server         *CentralServer
	storage        *StorageEngine
	width          int
	height         int
	events         []*StoredEvent
	filteredEvents []*StoredEvent
	incidents      []*StoredEvent
	nodes          []NodeSession
	activeBans     []ActiveBanRecord
	soarActions    []SOARActionRecord
	mitreMap       map[string]int
	attackerMap    map[string]*attackerIntel
	targetMap      map[string]int
	totalTargetReq int
	activeTab      int // 0: Fleet, 1: Live Stream, 2: Critical Incidents, 3: MITRE
	activeLogTab   LogTab
	rateHistory    []int
	peakEPS        int
	statusPrompt   string
	isPaused       bool

	// Entropy & Kill Chain
	recentEntropies []float64
	avgEntropy      float64
	killChainHits   map[string]int

	// Threat Hunting Search
	searchQuery    string
	isFilterActive bool
	inputSearch    string

	// Multi-Node Fleet & Sensor Tree State
	fleetTree            []*FleetTreeNode
	treeExpansionState   map[string]bool
	selectedTreeIndex    int
	selectedNodeFilter   string // Empty string = All Nodes, otherwise filtered to specific NodeID
	selectedSensorFilter string // Empty string = All Sensors, otherwise "nginx", "auth", "suricata", "audit", "syslog"

	// Dual-Panel Focus & Scroll State
	activeFocus      FocusPanel
	logScroll        int
	selectedLogIndex int
	logScrollOffset  int

	selectedIncIndex int
	incScrollOffset  int

	inspectEvent *StoredEvent

	// Async Ring Buffer Queue
	mu          sync.Mutex
	eventBuffer []*StoredEvent

	// Modal State
	mode    modalMode
	inputIP string
}

var (
	tuiLogMu   sync.Mutex
	tuiLogPool []*StoredEvent
)

// PushLogToTUI is a thread-safe, non-blocking log intake called directly by CentralServer.
func PushLogToTUI(ev *StoredEvent) {
	if ev == nil {
		return
	}
	tuiLogMu.Lock()
	defer tuiLogMu.Unlock()
	if len(tuiLogPool) < 2000 {
		tuiLogPool = append(tuiLogPool, ev)
	}
}

// LogEventMsg encapsulates an event dispatched directly from gRPC stream to TUI.
type LogEventMsg struct {
	Event *StoredEvent
}

// NewSIEMModel creates a high-performance strictly-bounded 6-panel TUI model.
func NewSIEMModel(server *CentralServer, storage *StorageEngine) *SIEMModel {
	m := &SIEMModel{
		server:             server,
		storage:            storage,
		activeTab:          1,
		activeLogTab:       TabAll,
		treeExpansionState: make(map[string]bool),
		mitreMap:           make(map[string]int),
		attackerMap:        make(map[string]*attackerIntel),
		targetMap:          make(map[string]int),
		killChainHits:      make(map[string]int),
		rateHistory:        make([]int, 20),
		recentEntropies:    make([]float64, 0, 30),
		events:             make([]*StoredEvent, 0, 250),
		incidents:          make([]*StoredEvent, 0, 120),
	}

	defaultCore := []string{"T1190", "T1059.004", "T1203", "T1078", "T1053.003", "T1548.001", "T1027", "T1070.003", "T1562.001", "T1110.001", "T1003.008", "T1552.001", "T1595.002", "T1082", "T1087.001", "T1046", "T1071.001", "T1041", "T1567"}
	for _, t := range defaultCore {
		m.mitreMap[t] = 0
	}

	if stats, err := storage.GetMITREStats(); err == nil {
		for _, s := range stats {
			m.mitreMap[s.TechniqueID] = s.Count
		}
	}
	if evs, err := storage.GetRecentEvents(100); err == nil && len(evs) > 0 {
		m.events = evs
	}
	if incs, err := storage.GetCriticalEvents(40); err == nil && len(incs) > 0 {
		m.incidents = incs
	}
	if bans, err := storage.GetActiveBans(); err == nil {
		m.activeBans = bans
	}
	if actions, err := storage.GetRecentSOARActions(5); err == nil {
		m.soarActions = actions
	}

	m.rebuildFleetTree()

	// Async non-blocking subscriber
	go func() {
		sub := server.SubscribeEvents()
		for ev := range sub {
			m.mu.Lock()
			m.eventBuffer = append(m.eventBuffer, ev)
			if len(m.eventBuffer) > 2000 {
				m.eventBuffer = m.eventBuffer[1000:]
			}
			m.mu.Unlock()
		}
	}()

	return m
}

func (m *SIEMModel) Init() tea.Cmd {
	return m.tickCmd()
}

func (m *SIEMModel) tickCmd() tea.Cmd {
	return tea.Tick(33*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func lookupGeoThreatActor(ip string) (flag, org, class string) {
	if strings.HasPrefix(ip, "185.220.") || strings.HasPrefix(ip, "185.222.") || strings.HasPrefix(ip, "104.244.") {
		return "🇩🇪", "Tor Project", "Tor Exit"
	} else if strings.HasPrefix(ip, "161.35.") || strings.HasPrefix(ip, "164.92.") || strings.HasPrefix(ip, "159.65.") {
		return "🇩🇪", "DigitalOcean", "Scanner"
	} else if strings.HasPrefix(ip, "45.154.") || strings.HasPrefix(ip, "194.26.") || strings.HasPrefix(ip, "193.106.") {
		return "🇷🇺", "Selectel", "Exploiter"
	} else if strings.HasPrefix(ip, "43.135.") || strings.HasPrefix(ip, "119.28.") || strings.HasPrefix(ip, "124.222.") {
		return "🇨🇳", "Tencent Cloud", "Crawler"
	} else if strings.HasPrefix(ip, "176.") || strings.HasPrefix(ip, "88.") || strings.HasPrefix(ip, "212.") || strings.HasPrefix(ip, "78.") {
		return "🇹🇷", "Turkcell/ISP", "WAN User"
	} else if strings.HasPrefix(ip, "34.") || strings.HasPrefix(ip, "35.") || strings.HasPrefix(ip, "54.") || strings.HasPrefix(ip, "52.") {
		return "🇺🇸", "AWS/GCP Cloud", "Cloud Host"
	} else if strings.HasPrefix(ip, "198.51.100.") || strings.HasPrefix(ip, "203.0.113.") {
		return "🧪", "RedTeam Lab", "Threat Test"
	}
	return "🌐", "Public WAN", "Unknown"
}

func extractTarget(rawLine string) string {
	parts := strings.Fields(rawLine)
	for _, p := range parts {
		if strings.HasPrefix(p, "/") {
			idx := strings.Index(p, "?")
			if idx != -1 {
				p = p[:idx]
			}
			if len(p) > 20 {
				return p[:20]
			}
			return p
		}
	}
	if strings.Contains(rawLine, "SSH") || strings.Contains(rawLine, "password") {
		return "sshd:root"
	}
	return "web:root"
}

// safeText cuts text cleanly at limit only if it actually exceeds limit.
func safeText(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit])
}

// hardTruncate delegates to safeText without forcing ellipsis.
func hardTruncate(s string, maxLen int) string {
	return safeText(s, maxLen)
}

// cleanForTerminal cleans non-printable ASCII, null-bytes, and control codes that break terminal layout.
func cleanForTerminal(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 32 && r <= 126) || r == '\n' || r == '\t' {
			b.WriteRune(r)
		} else {
			b.WriteString(".")
		}
	}
	res := b.String()
	res = strings.ReplaceAll(res, "\n", " ")
	res = strings.ReplaceAll(res, "\r", " ")
	return res
}

// renderModal isolates the modal layer with a solid background and centered placement.
func renderModal(content string, width, height int) string {
	modalStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00F0FF")).
		Background(lipgloss.Color("#0D1117")).
		Padding(1, 2).
		Width(min(80, max(20, width-10))).
		MaxHeight(max(10, height-4))

	modalBox := modalStyle.Render(content)

	return lipgloss.Place(
		width,
		height,
		lipgloss.Center,
		lipgloss.Center,
		modalBox,
		lipgloss.WithWhitespaceChars(" "),
		lipgloss.WithWhitespaceForeground(lipgloss.Color("#000000")),
	)
}

func (m *SIEMModel) rebuildFleetTree() {
	if len(m.nodes) == 0 {
		localID := "vps-df28810e"
		expanded, ok := m.treeExpansionState[localID]
		if !ok {
			expanded = true
			m.treeExpansionState[localID] = true
		}
		m.fleetTree = []*FleetTreeNode{
			{
				ID:         localID,
				Label:      localID + " [ONLINE]",
				Type:       NodeHost,
				ParentHost: "",
				Expanded:   expanded,
				Children: []*FleetTreeNode{
					{ID: localID + ":nginx", Label: "Nginx Web Server", Type: NodeSensor, ParentHost: localID, SensorKey: "nginx"},
					{ID: localID + ":auth", Label: "OpenSSH & Auth", Type: NodeSensor, ParentHost: localID, SensorKey: "auth"},
					{ID: localID + ":suricata", Label: "Suricata IDS/IPS", Type: NodeSensor, ParentHost: localID, SensorKey: "suricata"},
					{ID: localID + ":audit", Label: "Linux Kernel Audit", Type: NodeSensor, ParentHost: localID, SensorKey: "audit"},
					{ID: localID + ":syslog", Label: "Systemd Syslog", Type: NodeSensor, ParentHost: localID, SensorKey: "syslog"},
				},
			},
		}
		return
	}

	var tree []*FleetTreeNode
	for _, n := range m.nodes {
		expanded, ok := m.treeExpansionState[n.NodeID]
		if !ok {
			expanded = true
			m.treeExpansionState[n.NodeID] = true
		}

		hostNode := &FleetTreeNode{
			ID:         n.NodeID,
			Label:      n.NodeID + " [ONLINE]",
			Type:       NodeHost,
			ParentHost: "",
			Expanded:   expanded,
			Children: []*FleetTreeNode{
				{ID: n.NodeID + ":nginx", Label: "Nginx Web Server", Type: NodeSensor, ParentHost: n.NodeID, SensorKey: "nginx"},
				{ID: n.NodeID + ":auth", Label: "OpenSSH & Auth", Type: NodeSensor, ParentHost: n.NodeID, SensorKey: "auth"},
				{ID: n.NodeID + ":suricata", Label: "Suricata IDS/IPS", Type: NodeSensor, ParentHost: n.NodeID, SensorKey: "suricata"},
				{ID: n.NodeID + ":audit", Label: "Linux Kernel Audit", Type: NodeSensor, ParentHost: n.NodeID, SensorKey: "audit"},
				{ID: n.NodeID + ":syslog", Label: "Systemd Syslog", Type: NodeSensor, ParentHost: n.NodeID, SensorKey: "syslog"},
			},
		}
		tree = append(tree, hostNode)
	}
	m.fleetTree = tree
}

func (m *SIEMModel) getFlattenedTree() []*FleetTreeNode {
	var flat []*FleetTreeNode
	for _, node := range m.fleetTree {
		flat = append(flat, node)
		if node.Expanded {
			for _, child := range node.Children {
				flat = append(flat, child)
			}
		}
	}
	return flat
}

func (m *SIEMModel) renderTabBar() string {
	tabs := []string{"[1] INCIDENTS", "[2] ALL", "[3] NGINX", "[4] AUTH", "[5] SURICATA", "[6] AUDIT"}
	var items []string
	for i, t := range tabs {
		if LogTab(i) == m.activeLogTab {
			items = append(items, lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#0D1117")).
				Background(lipgloss.Color("#00FFC2")).
				Padding(0, 1).
				Render(t))
		} else {
			items = append(items, lipgloss.NewStyle().
				Foreground(lipgloss.Color("#64748B")).
				Padding(0, 1).
				Render(t))
		}
	}
	return strings.Join(items, " ")
}

func renderTree(nodes []*FleetTreeNode, selectedIdx int, currentIdx *int) string {
	var b strings.Builder
	for _, node := range nodes {
		cursor := "  "
		if *currentIdx == selectedIdx {
			cursor = "👉"
		}

		if node.Type == NodeHost {
			icon := "▼"
			if !node.Expanded {
				icon = "▶"
			}
			b.WriteString(fmt.Sprintf("%s %s %s\n", cursor, icon, node.Label))
			*currentIdx++
			if node.Expanded {
				numChildren := len(node.Children)
				for ci, child := range node.Children {
					childCursor := "    "
					if *currentIdx == selectedIdx {
						childCursor = "  👉"
					}
					branch := "├──"
					if ci == numChildren-1 {
						branch = "└──"
					}
					b.WriteString(fmt.Sprintf("%s %s %s\n", childCursor, branch, child.Label))
					*currentIdx++
				}
			}
		}
	}
	return b.String()
}

func (m *SIEMModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case *StoredEvent:
		m.processIncomingEvent(msg)
		return m, nil

	case LogEventMsg:
		if msg.Event != nil {
			m.processIncomingEvent(msg.Event)
		}
		return m, nil

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		if m.mode != modalNone {
			switch msg.String() {
			case "esc":
				if m.mode == modalSearch && m.isFilterActive {
					m.isFilterActive = false
					m.searchQuery = ""
					m.filteredEvents = nil
					m.selectedLogIndex = 0
					m.logScrollOffset = 0
					m.statusPrompt = "🔍 Search filter cleared"
				}
				m.mode = modalNone
				m.inspectEvent = nil
				m.inputIP = ""
				m.inputSearch = ""
				return m, nil
			case "enter":
				if m.mode == modalLogDetail {
					m.mode = modalNone
					m.inspectEvent = nil
					return m, nil
				} else if m.mode == modalSearch {
					m.executeSearch()
					return m, nil
				}
				m.submitModal()
				return m, nil
			case "backspace":
				if m.mode == modalSearch {
					if len(m.inputSearch) > 0 {
						m.inputSearch = m.inputSearch[:len(m.inputSearch)-1]
					}
				} else if len(m.inputIP) > 0 {
					m.inputIP = m.inputIP[:len(m.inputIP)-1]
				}
			default:
				if len(msg.String()) == 1 && m.mode != modalLogDetail {
					if m.mode == modalSearch {
						m.inputSearch += msg.String()
					} else {
						m.inputIP += msg.String()
					}
				}
			}
			return m, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "1":
			m.activeLogTab = TabIncidents
			m.selectedLogIndex = 0
			m.logScrollOffset = 0
			m.statusPrompt = "🔥 Tab: [1] INCIDENTS"
		case "2":
			m.activeLogTab = TabAll
			m.selectedLogIndex = 0
			m.logScrollOffset = 0
			m.statusPrompt = "🌐 Tab: [2] ALL LIVE STREAM"
		case "3":
			m.activeLogTab = TabNginx
			m.selectedLogIndex = 0
			m.logScrollOffset = 0
			m.statusPrompt = "⚡ Tab: [3] NGINX ACCESS"
		case "4":
			m.activeLogTab = TabAuth
			m.selectedLogIndex = 0
			m.logScrollOffset = 0
			m.statusPrompt = "🔑 Tab: [4] SSH & AUTH"
		case "5":
			m.activeLogTab = TabSuricata
			m.selectedLogIndex = 0
			m.logScrollOffset = 0
			m.statusPrompt = "🛡️ Tab: [5] SURICATA IDS"
		case "6":
			m.activeLogTab = TabAuditSyslog
			m.selectedLogIndex = 0
			m.logScrollOffset = 0
			m.statusPrompt = "🔬 Tab: [6] AUDIT & KERNEL"
		case "tab", "shift+tab":
			if m.activeFocus == FocusTree {
				m.activeFocus = FocusLogs
				m.statusPrompt = "🎯 Focus: [MIDDLE LOG STREAM] (j/k: scroll, Enter/i: inspect, G: latest)"
			} else {
				m.activeFocus = FocusTree
				m.statusPrompt = "🎯 Focus: [LEFT FLEET TREE] (↑/↓: select, Enter/Space: expand/lock)"
			}
		case "a", "A":
			m.selectedNodeFilter = ""
			m.selectedSensorFilter = ""
			m.selectedLogIndex = 0
			m.logScrollOffset = 0
			m.statusPrompt = "🌐 Fleet Focus: ALL NODES & SENSORS"
		case "/", "f":
			m.mode = modalSearch
			m.inputSearch = m.searchQuery
		case "esc":
			if m.isFilterActive {
				m.isFilterActive = false
				m.searchQuery = ""
				m.filteredEvents = nil
				m.selectedLogIndex = 0
				m.logScrollOffset = 0
				m.statusPrompt = "🔍 Search filter cleared"
			} else if m.selectedSensorFilter != "" || m.selectedNodeFilter != "" {
				m.selectedSensorFilter = ""
				m.selectedNodeFilter = ""
				m.selectedLogIndex = 0
				m.logScrollOffset = 0
				m.statusPrompt = "🌐 Sensor filter lock cleared (Showing all streams)"
			}
		case "up", "w":
			if m.activeFocus == FocusTree {
				if m.selectedTreeIndex > 0 {
					m.selectedTreeIndex--
				}
			} else {
				if m.selectedLogIndex > 0 {
					m.selectedLogIndex--
					if m.selectedLogIndex < m.logScrollOffset {
						m.logScrollOffset = m.selectedLogIndex
					}
				}
			}
		case "down", "s":
			if m.activeFocus == FocusTree {
				flat := m.getFlattenedTree()
				if m.selectedTreeIndex < len(flat)-1 {
					m.selectedTreeIndex++
				}
			} else {
				currentList := m.getCurrentEventsList()
				if m.selectedLogIndex < len(currentList)-1 {
					m.selectedLogIndex++
				}
			}
		case "k":
			if m.activeFocus == FocusTree {
				if m.selectedTreeIndex > 0 {
					m.selectedTreeIndex--
				}
			} else {
				if m.selectedLogIndex > 0 {
					m.selectedLogIndex--
					if m.selectedLogIndex < m.logScrollOffset {
						m.logScrollOffset = m.selectedLogIndex
					}
				}
			}
		case "j":
			if m.activeFocus == FocusTree {
				flat := m.getFlattenedTree()
				if m.selectedTreeIndex < len(flat)-1 {
					m.selectedTreeIndex++
				}
			} else {
				currentList := m.getCurrentEventsList()
				if m.selectedLogIndex < len(currentList)-1 {
					m.selectedLogIndex++
				}
			}
		case "pgup", "ctrl+u":
			m.selectedLogIndex = max(0, m.selectedLogIndex-10)
			m.logScrollOffset = max(0, m.logScrollOffset-10)
		case "pgdown", "ctrl+d":
			currentList := m.getCurrentEventsList()
			if len(currentList) > 0 {
				m.selectedLogIndex = min(len(currentList)-1, m.selectedLogIndex+10)
			}
		case "G", "end":
			m.selectedLogIndex = 0
			m.logScrollOffset = 0
			m.statusPrompt = "⚡ Auto-scroll: Locked to newest live logs"
		case "g", "home":
			currentList := m.getCurrentEventsList()
			if len(currentList) > 0 {
				m.selectedLogIndex = len(currentList) - 1
				m.statusPrompt = "📜 Scrolled to oldest retained log"
			}
		case "enter":
			if m.activeFocus == FocusTree {
				flat := m.getFlattenedTree()
				if len(flat) > 0 && m.selectedTreeIndex >= 0 && m.selectedTreeIndex < len(flat) {
					node := flat[m.selectedTreeIndex]
					if node.Type == NodeHost {
						node.Expanded = !node.Expanded
						m.treeExpansionState[node.ID] = node.Expanded
						m.rebuildFleetTree()
						stateStr := "Expanded"
						if !node.Expanded {
							stateStr = "Collapsed"
						}
						m.statusPrompt = fmt.Sprintf("🖥️ Host %s: %s", node.ID, stateStr)
					} else if node.Type == NodeSensor {
						if m.selectedNodeFilter == node.ParentHost && m.selectedSensorFilter == node.SensorKey {
							m.selectedNodeFilter = ""
							m.selectedSensorFilter = ""
							m.statusPrompt = "🌐 Sensor Lock Cleared (All Streams)"
						} else {
							m.selectedNodeFilter = node.ParentHost
							m.selectedSensorFilter = node.SensorKey
							m.selectedLogIndex = 0
							m.logScrollOffset = 0
							m.statusPrompt = fmt.Sprintf("🔒 Filter Locked: Host=%s Sensor=%s (Press ESC to Reset)", node.ParentHost, node.SensorKey)
						}
					}
				}
			} else {
				currentList := m.getCurrentEventsList()
				if len(currentList) > 0 && m.selectedLogIndex < len(currentList) {
					m.inspectEvent = currentList[m.selectedLogIndex]
					m.mode = modalLogDetail
				}
			}
		case " ":
			if m.activeFocus == FocusTree {
				flat := m.getFlattenedTree()
				if len(flat) > 0 && m.selectedTreeIndex >= 0 && m.selectedTreeIndex < len(flat) {
					node := flat[m.selectedTreeIndex]
					if node.Type == NodeHost {
						node.Expanded = !node.Expanded
						m.treeExpansionState[node.ID] = node.Expanded
						m.rebuildFleetTree()
					} else if node.Type == NodeSensor {
						if m.selectedNodeFilter == node.ParentHost && m.selectedSensorFilter == node.SensorKey {
							m.selectedNodeFilter = ""
							m.selectedSensorFilter = ""
						} else {
							m.selectedNodeFilter = node.ParentHost
							m.selectedSensorFilter = node.SensorKey
							m.selectedLogIndex = 0
							m.logScrollOffset = 0
						}
					}
				}
			} else {
				m.isPaused = !m.isPaused
				if m.isPaused {
					m.statusPrompt = "⏸️ Stream Paused"
				} else {
					m.statusPrompt = "▶️ Stream Resumed"
				}
			}
		case "i", "o":
			currentList := m.getCurrentEventsList()
			if len(currentList) > 0 && m.selectedLogIndex < len(currentList) {
				m.inspectEvent = currentList[m.selectedLogIndex]
				m.mode = modalLogDetail
			}
		case "p":
			m.isPaused = !m.isPaused
			if m.isPaused {
				m.statusPrompt = "⏸️ Stream Paused"
			} else {
				m.statusPrompt = "▶️ Stream Resumed"
			}
		case "b":
			m.mode = modalBanIP
			m.inputIP = ""
		case "u":
			m.mode = modalUnbanIP
			m.inputIP = ""
		case "c":
			m.statusPrompt = ""
		}

	case tickMsg:
		// 1. Drain global thread-safe batching pool
		tuiLogMu.Lock()
		poolBatch := tuiLogPool
		tuiLogPool = nil
		tuiLogMu.Unlock()

		for _, ev := range poolBatch {
			m.processIncomingEvent(ev)
		}

		// 2. Drain internal subscriber buffer
		m.mu.Lock()
		buffered := m.eventBuffer
		m.eventBuffer = nil
		m.mu.Unlock()

		for _, ev := range buffered {
			m.processIncomingEvent(ev)
		}

		m.nodes = m.server.GetNodesSnapshot()
		m.rebuildFleetTree()

		if bans, err := m.storage.GetActiveBans(); err == nil {
			m.activeBans = bans
		}
		if actions, err := m.storage.GetRecentSOARActions(3); err == nil {
			m.soarActions = actions
		}

		eps := int(m.server.GetEPS())
		if eps > m.peakEPS {
			m.peakEPS = eps
		}
		m.rateHistory = append(m.rateHistory[1:], eps)

		return m, m.tickCmd()
	}

	return m, nil
}

func (m *SIEMModel) processIncomingEvent(ev *StoredEvent) {
	if ev == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isPaused && !m.isFilterActive {
		m.events = append([]*StoredEvent{ev}, m.events...)
		if m.selectedLogIndex > 0 {
			m.selectedLogIndex++
			m.logScrollOffset++
		}
		if len(m.events) > 250 {
			m.events = m.events[:250]
		}
	}
	if ev.ThreatScore >= 40 {
		m.incidents = append([]*StoredEvent{ev}, m.incidents...)
		if m.selectedIncIndex > 0 {
			m.selectedIncIndex++
			m.incScrollOffset++
		}
		if len(m.incidents) > 120 {
			m.incidents = m.incidents[:120]
		}
	}
	if ev.MitreTechniqueID != "" {
		m.mitreMap[ev.MitreTechniqueID]++
		if strings.HasPrefix(ev.MitreTechniqueID, "T1595") || strings.HasPrefix(ev.MitreTechniqueID, "T1590") {
			m.killChainHits["Recon"]++
		} else if strings.HasPrefix(ev.MitreTechniqueID, "T1190") {
			m.killChainHits["Initial"]++
		} else if strings.HasPrefix(ev.MitreTechniqueID, "T1059") || strings.HasPrefix(ev.MitreTechniqueID, "T1203") {
			m.killChainHits["Execution"]++
		} else if strings.HasPrefix(ev.MitreTechniqueID, "T1078") || strings.HasPrefix(ev.MitreTechniqueID, "T1053") {
			m.killChainHits["Persist"]++
		} else if strings.HasPrefix(ev.MitreTechniqueID, "T1041") || strings.HasPrefix(ev.MitreTechniqueID, "T1567") {
			m.killChainHits["Exfil"]++
		}
	}

	target := extractTarget(ev.RawLine)
	m.targetMap[target]++
	m.totalTargetReq++

	ent := CalculateShannonEntropy(ev.RawLine)
	m.recentEntropies = append(m.recentEntropies, ent)
	if len(m.recentEntropies) > 30 {
		m.recentEntropies = m.recentEntropies[1:]
	}

	if len(m.recentEntropies) > 0 {
		var sum float64
		for _, v := range m.recentEntropies {
			sum += v
		}
		m.avgEntropy = sum / float64(len(m.recentEntropies))
	}

	if ev.ClientIP != "" && ev.ClientIP != "127.0.0.1" {
		if existing, ok := m.attackerMap[ev.ClientIP]; ok {
			existing.Count++
			if existing.TopTarget == "" {
				existing.TopTarget = target
			}
		} else {
			flag, org, class := lookupGeoThreatActor(ev.ClientIP)
			m.attackerMap[ev.ClientIP] = &attackerIntel{
				IP:        ev.ClientIP,
				Flag:      flag,
				Org:       org,
				Class:     class,
				Count:     1,
				TopTarget: target,
			}
		}
	}
}

func (m *SIEMModel) getCurrentEventsList() []*StoredEvent {
	list := m.events
	if m.isFilterActive {
		list = m.filteredEvents
	}

	var filtered []*StoredEvent
	for _, ev := range list {
		// 1. Tab Filter
		switch m.activeLogTab {
		case TabIncidents:
			if ev.ThreatScore < 40 && ev.StatusCode < 400 && ev.RuleID == "" {
				continue
			}
		case TabSuricata:
			if ev.Source != "suricata" && !strings.Contains(strings.ToLower(ev.RawLine), "suricata") {
				continue
			}
		case TabNginx:
			if ev.Source != "nginx" {
				continue
			}
		case TabAuth:
			if ev.Source != "auth" && ev.Source != "ssh" {
				continue
			}
		case TabAuditSyslog:
			if ev.Source != "audit" && ev.Source != "syslog" {
				continue
			}
		case TabAll:
			// No source filtering
		}

		// 2. Tree Host Filter Lock
		if m.selectedNodeFilter != "" && ev.NodeID != m.selectedNodeFilter {
			continue
		}

		// 3. Tree Sensor Filter Lock
		if m.selectedSensorFilter != "" {
			src := ev.Source
			if m.selectedSensorFilter == "auth" {
				if src != "auth" && src != "ssh" {
					continue
				}
			} else if m.selectedSensorFilter == "audit" {
				if src != "audit" {
					continue
				}
			} else if src != m.selectedSensorFilter {
				continue
			}
		}

		filtered = append(filtered, ev)
	}
	return filtered
}

func (m *SIEMModel) getCurrentIncidentsList() []*StoredEvent {
	if m.selectedNodeFilter == "" {
		return m.incidents
	}
	var filtered []*StoredEvent
	for _, ev := range m.incidents {
		if ev.NodeID == m.selectedNodeFilter {
			filtered = append(filtered, ev)
		}
	}
	return filtered
}

func (m *SIEMModel) executeSearch() {
	query := strings.TrimSpace(m.inputSearch)
	m.mode = modalNone
	if query == "" {
		m.isFilterActive = false
		m.searchQuery = ""
		m.filteredEvents = nil
		m.selectedLogIndex = 0
		m.logScrollOffset = 0
		return
	}

	results, err := m.storage.SearchEvents(query, 100)
	if err != nil {
		m.statusPrompt = fmt.Sprintf("⚠️ Search error: %v", err)
		return
	}

	m.isFilterActive = true
	m.searchQuery = query
	m.filteredEvents = results
	m.selectedLogIndex = 0
	m.logScrollOffset = 0
	m.statusPrompt = fmt.Sprintf("🔍 Filter active: '%s' (%d Hits) - Press ESC to Clear", query, len(results))
}

func (m *SIEMModel) submitModal() {
	ip := strings.TrimSpace(m.inputIP)
	if ip == "" {
		m.mode = modalNone
		return
	}

	switch m.mode {
	case modalBanIP:
		dispatched := m.server.BroadcastSOARCommand("BAN_IP", ip, 86400)
		m.statusPrompt = fmt.Sprintf("🚫 Global Fleet Ban executed for %s across %d nodes", ip, dispatched)
	case modalUnbanIP:
		dispatched := m.server.BroadcastSOARCommand("UNBAN_IP", ip, 0)
		m.statusPrompt = fmt.Sprintf("🔓 Global Unban executed for %s across %d nodes", ip, dispatched)
	}

	m.mode = modalNone
	m.inputIP = ""
}

// fitLines clips string output to exactly maxLines rows to guarantee zero overflow.
func fitLines(content string, maxLines int) string {
	if maxLines <= 0 {
		return ""
	}
	lines := strings.Split(content, "\n")
	if len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	return strings.Join(lines, "\n")
}

func (m *SIEMModel) getBorderColor(panel FocusPanel) string {
	if m.activeFocus == panel {
		return "#00FFC2" // Aktif panel vurgusu (Cyan/Mint)
	}
	return "#1E293B" // Pasif panel sınırları (Koyu Gri/Mavi)
}

func (m *SIEMModel) View() string {
	if m.width < 100 || m.height < 20 {
		return lipgloss.Place(
			m.width,
			m.height,
			lipgloss.Center,
			lipgloss.Center,
			"Terminal boyutu çok küçük. Lütfen terminali genişletin (Min: 100x20).",
		)
	}

	if m.mode == modalLogDetail {
		return m.renderInspectionModal()
	} else if m.mode == modalSearch {
		return m.renderSearchModalOverlay()
	} else if m.mode != modalNone {
		return m.renderModalOverlay()
	}

	availH := m.height - 2 // Alt footer durum çubuğu payı

	// --- 1. SİMETRİK GRID GENİŞLİK DAĞILIMI ---
	leftW := 30  // "📁 FLEET TREE" ve sensörler için ideal genişlik
	rightW := 34 // MITRE ve SOAR için taşmayan genişlik
	centerW := m.width - leftW - rightW - 2

	if centerW < 40 {
		centerW = 40
	}

	// --- 2. SOL PANEL (FLEET TREE) ---
	treeHeaderStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFC2"))
	leftInner := fmt.Sprintf("%s\n%s\n%s",
		treeHeaderStyle.Render("📁 FLEET TREE"),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#334155")).Render(strings.Repeat("─", leftW-4)),
		m.renderTreeLines(leftW-4, availH-5),
	)

	leftPanel := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(m.getBorderColor(FocusTree))).
		Width(leftW - 2).
		Height(availH - 2).
		Render(leftInner)

	// --- 3. ORTA PANEL (UNIFIED TAB STREAM) ---
	centerPanel := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(m.getBorderColor(FocusLogs))).
		Width(centerW - 2).
		Height(availH - 2).
		Render(fitLines(m.renderCenterPanelContent(centerW-4, availH-4), availH-4))

	// --- 4. SAĞ PANEL (MITRE + SOAR DİKEY BÖLÜNMÜŞ) ---
	totalRightInnerH := availH - 2
	mitreH := totalRightInnerH / 2
	soarH := totalRightInnerH - mitreH

	mitreInner := fmt.Sprintf("%s\n%s",
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFC2")).Render("🛡️ MITRE ATT&CK"),
		m.renderMitreList(rightW-4, mitreH-3),
	)

	soarInner := fmt.Sprintf("%s\n%s",
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF3366")).Render("🛑 SOAR MITIGATION"),
		m.renderSoarList(rightW-4, soarH-3),
	)

	mitreBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#334155")).
		Width(rightW - 2).
		Height(mitreH).
		Render(mitreInner)

	soarBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#334155")).
		Width(rightW - 2).
		Height(soarH).
		Render(soarInner)

	rightPanel := lipgloss.JoinVertical(lipgloss.Left, mitreBox, soarBox)

	// --- 5. ANA EKRAN BİRLEŞTİRME ---
	mainView := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, centerPanel, rightPanel)
	footer := m.renderFooterBar()

	return lipgloss.JoinVertical(lipgloss.Left, mainView, footer)
}

func (m *SIEMModel) renderTreeLines(width, maxLines int) string {
	m.rebuildFleetTree()

	currentIdx := 0
	treeStr := renderTree(m.fleetTree, m.selectedTreeIndex, &currentIdx)
	treeLines := strings.Split(strings.TrimRight(treeStr, "\n"), "\n")

	var b strings.Builder
	linesWritten := 0
	for _, line := range treeLines {
		if linesWritten >= maxLines-1 {
			break
		}
		b.WriteString(safeText(line, width) + "\n")
		linesWritten++
	}

	if linesWritten < maxLines {
		hint := "[↑/↓] Move [Enter] Lock"
		b.WriteString(safeText(styleMuted.Render(hint), width))
	}

	return b.String()
}

func (m *SIEMModel) renderCenterPanelContent(w, h int) string {
	header := m.renderTabBar()
	divider := styleMuted.Render(strings.Repeat("─", max(2, w)))

	availLogLines := h - 2
	if availLogLines < 1 {
		availLogLines = 1
	}

	var logLines []string
	if m.activeLogTab == TabIncidents {
		// Sekme 1 ise SADECE Incident listesini tam boy bas
		logLines = m.renderIncidentLogs(w, availLogLines)
	} else {
		// Diğer sekmeler ise seçili filtrenin ham log akışını tam boy bas
		logLines = m.renderStreamLogs(w, availLogLines)
	}

	return fmt.Sprintf("%s\n%s\n%s", header, divider, strings.Join(logLines, "\n"))
}

func renderMiniBar(pct float64, width int) string {
	if width <= 0 {
		width = 6
	}
	filled := int((pct / 100.0) * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func (m *SIEMModel) renderFleetPanel(width, maxLines int) string {
	var b strings.Builder
	titleText := "📁 FLEET TREE"
	if m.selectedNodeFilter != "" || m.selectedSensorFilter != "" {
		tag := m.selectedNodeFilter
		if m.selectedSensorFilter != "" {
			tag += ":" + m.selectedSensorFilter
		}
		titleText = fmt.Sprintf("📁 FLEET [%s]", safeText(tag, 16))
	}
	b.WriteString(safeText(styleMatrixTitle.Render(titleText), width) + "\n")
	b.WriteString(styleMuted.Render(strings.Repeat("─", max(2, width))) + "\n")

	m.rebuildFleetTree()

	currentIdx := 0
	treeStr := renderTree(m.fleetTree, m.selectedTreeIndex, &currentIdx)
	treeLines := strings.Split(strings.TrimRight(treeStr, "\n"), "\n")

	linesWritten := 2
	for _, line := range treeLines {
		if linesWritten >= maxLines-1 {
			break
		}
		b.WriteString(safeText(line, width) + "\n")
		linesWritten++
	}

	if linesWritten < maxLines {
		hint := "[↑/↓] Move [Enter] Lock"
		b.WriteString(safeText(styleMuted.Render(hint), width))
	}

	return b.String()
}

func (m *SIEMModel) renderMitreList(width, maxLines int) string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#334155")).Render(strings.Repeat("─", max(2, width))) + "\n")

	colHeader := fmt.Sprintf("%-10s %-12s %s", styleMuted.Render("[ID]"), styleMuted.Render("[Technique]"), styleMuted.Render("[Hits]"))
	b.WriteString(safeText(colHeader, width) + "\n")

	linesWritten := 2
	analyzer := m.server.GetAnalyzer()

	var list []techniqueStat
	for k, v := range m.mitreMap {
		name, tactic := "", ""
		if analyzer != nil {
			name, tactic = analyzer.GetTechniqueMeta(k)
		}
		if name == "" {
			name = k
		}
		list = append(list, techniqueStat{ID: k, Name: name, Tactic: tactic, Count: v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count == list[j].Count {
			return list[i].ID < list[j].ID
		}
		return list[i].Count > list[j].Count
	})

	for _, st := range list {
		if linesWritten >= maxLines {
			break
		}

		color := colorCyberCyan
		if st.Count >= 20 {
			color = colorAlertPink
		} else if st.Count >= 5 {
			color = colorWarningGold
		}

		techStr := lipgloss.NewStyle().Bold(true).Foreground(color).Render(fmt.Sprintf("%-10s", st.ID))
		hitsBadge := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFC2")).Render(fmt.Sprintf("[%3d]", st.Count))
		nameLen := max(6, width-20)
		row := fmt.Sprintf("%s %-12s %s", techStr, styleLight.Render(safeText(st.Name, nameLen)), hitsBadge)
		b.WriteString(safeText(row, width) + "\n")
		linesWritten++
	}

	return b.String()
}

func (m *SIEMModel) renderSoarList(width, maxLines int) string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#334155")).Render(strings.Repeat("─", max(2, width))) + "\n")

	linesWritten := 1
	if len(m.activeBans) == 0 {
		b.WriteString(safeText(styleMuted.Render("No active IP isolations."), width) + "\n")
		b.WriteString(safeText(styleMuted.Render("Perimeter defense idle."), width) + "\n")
		linesWritten += 2
	} else {
		for _, ban := range m.activeBans {
			if linesWritten >= maxLines {
				break
			}
			elapsedSec := (time.Now().UnixMilli() - ban.BanTimeMs) / 1000
			remSec := ban.DurationSeconds - elapsedSec
			remStr := fmt.Sprintf("%dm", remSec/60)
			if remSec <= 0 {
				remStr = "exp"
			}

			reason := ban.Reason
			if len(reason) > 8 {
				reason = reason[:8]
			}

			line := fmt.Sprintf("🚫 %-15s %-7s %s", safeText(ban.IP, 15), styleWarning.Render(reason), remStr)
			b.WriteString(safeText(line, width) + "\n")
			linesWritten++
		}
	}

	if linesWritten < maxLines && len(m.soarActions) > 0 {
		act := m.soarActions[0]
		ackLine := fmt.Sprintf("[ACK] %s %s (%dn)", act.ActionType, safeText(act.TargetIP, 14), act.NodesCount)
		b.WriteString(safeText(styleGreen.Render(ackLine), width))
	}
	return b.String()
}

func (m *SIEMModel) renderJailPanel(width, maxLines int) string {
	return m.renderSoarList(width, maxLines)
}

func (m *SIEMModel) renderStreamLogs(width, availableLines int) []string {
	currentList := m.getCurrentEventsList()
	if len(currentList) == 0 {
		if m.isFilterActive {
			return []string{hardTruncate(styleWarning.Render("No entries match search query. [Esc] to Clear."), width)}
		} else if m.selectedSensorFilter != "" {
			return []string{hardTruncate(styleWarning.Render(fmt.Sprintf("No logs for sensor [%s]. Waiting for events...", m.selectedSensorFilter)), width)}
		}
		return []string{hardTruncate(styleMuted.Render("Listening for edge node stream events..."), width)}
	}

	visibleItems := availableLines / 2
	if visibleItems <= 0 {
		visibleItems = 1
	}

	if m.selectedLogIndex < m.logScrollOffset {
		m.logScrollOffset = m.selectedLogIndex
	} else if m.selectedLogIndex >= m.logScrollOffset+visibleItems {
		m.logScrollOffset = m.selectedLogIndex - visibleItems + 1
	}

	var lines []string
	for i := 0; i < visibleItems; i++ {
		idx := m.logScrollOffset + i
		if idx >= len(currentList) {
			break
		}

		ev := currentList[idx]
		timeStr := time.UnixMilli(ev.TimestampMs).Format("15:04:05")
		srcIcon := "🌐 HTTP"
		switch ev.Source {
		case "auth", "ssh":
			srcIcon = "🔑 AUTH"
		case "suricata":
			srcIcon = "🛡️ SURICATA"
		case "audit":
			srcIcon = "🔬 AUDIT"
		case "syslog":
			srcIcon = "📜 SYS"
		}

		scoreBadge := styleGreen.Render(fmt.Sprintf("[%d]", ev.ThreatScore))
		if ev.ThreatScore >= 80 {
			scoreBadge = styleAlert.Render(fmt.Sprintf("[%d]", ev.ThreatScore))
		} else if ev.ThreatScore >= 50 {
			scoreBadge = styleWarning.Render(fmt.Sprintf("[%d]", ev.ThreatScore))
		}

		prefix := "  "
		if idx == m.selectedLogIndex {
			prefix = "▶ "
		}

		scrollChar := styleScrollTrack.Render("│")
		if len(currentList) > 1 && visibleItems > 1 {
			thumbPos := int(float64(m.selectedLogIndex) / float64(len(currentList)-1) * float64(visibleItems-1))
			if i == thumbPos {
				scrollChar = styleCyan.Render("█")
			}
		}

		contentWidth := max(10, width-2)
		clientIP := ev.ClientIP
		if clientIP == "" {
			clientIP = "local"
		}
		techID := ev.MitreTechniqueID
		if techID == "" {
			techID = "INFO"
		}

		line1 := fmt.Sprintf("%s%s %s %s 🎯 %s 🏷 %s",
			prefix,
			styleMuted.Render(timeStr),
			scoreBadge,
			styleCyan.Render(srcIcon),
			lipgloss.NewStyle().Bold(true).Foreground(colorTextLight).Render(clientIP),
			styleWarning.Render(techID),
		)
		line2 := fmt.Sprintf("    %s", styleMuted.Render(hardTruncate(cleanForTerminal(ev.RawLine), contentWidth-4)))

		formatted1 := hardTruncate(line1, contentWidth)
		formatted2 := hardTruncate(line2, contentWidth)
		padding1 := strings.Repeat(" ", max(0, contentWidth-lipgloss.Width(formatted1)))
		padding2 := strings.Repeat(" ", max(0, contentWidth-lipgloss.Width(formatted2)))

		if idx == m.selectedLogIndex && m.activeFocus == FocusLogs {
			lines = append(lines, styleSelected.Render(formatted1+padding1)+scrollChar)
			lines = append(lines, styleSelected.Render(formatted2+padding2)+scrollChar)
		} else {
			lines = append(lines, formatted1+padding1+scrollChar)
			lines = append(lines, formatted2+padding2+scrollChar)
		}
	}
	return lines
}

func (m *SIEMModel) renderIncidentLogs(width, availableLines int) []string {
	currentIncs := m.getCurrentIncidentsList()
	if len(currentIncs) == 0 {
		return []string{hardTruncate(styleMuted.Render("No critical incidents logged. Threat perimeter secure."), width)}
	}

	visibleItems := availableLines / 2
	if visibleItems <= 0 {
		visibleItems = 1
	}

	if m.selectedLogIndex < m.logScrollOffset {
		m.logScrollOffset = m.selectedLogIndex
	} else if m.selectedLogIndex >= m.logScrollOffset+visibleItems {
		m.logScrollOffset = m.selectedLogIndex - visibleItems + 1
	}

	var lines []string
	for i := 0; i < visibleItems; i++ {
		idx := m.logScrollOffset + i
		if idx >= len(currentIncs) {
			break
		}

		ev := currentIncs[idx]
		timeStr := time.UnixMilli(ev.TimestampMs).Format("15:04:05")

		scoreBadge := lipgloss.NewStyle().Bold(true).Foreground(colorAlertPink).Render(fmt.Sprintf("[%d]", ev.ThreatScore))
		prefix := "  "
		if idx == m.selectedLogIndex {
			prefix = "▶ "
		}

		scrollChar := styleScrollTrack.Render("│")
		if len(currentIncs) > 1 && visibleItems > 1 {
			thumbPos := int(float64(m.selectedLogIndex) / float64(len(currentIncs)-1) * float64(visibleItems-1))
			if i == thumbPos {
				scrollChar = styleAlert.Render("█")
			}
		}

		contentWidth := max(10, width-2)
		clientIP := ev.ClientIP
		if clientIP == "" {
			clientIP = "local"
		}
		rule := ev.RuleID
		if rule == "" {
			rule = "CRITICAL_ANOMALY"
		}

		line1 := fmt.Sprintf("%s%s %s 👤 %s 🏷 %s 🛡 %s",
			prefix,
			styleMuted.Render(timeStr),
			scoreBadge,
			lipgloss.NewStyle().Bold(true).Foreground(colorAlertPink).Render(clientIP),
			styleWarning.Render(ev.MitreTechniqueID),
			styleCyan.Render(hardTruncate(rule, 16)),
		)
		line2 := fmt.Sprintf("    %s", styleLight.Render(hardTruncate(cleanForTerminal(ev.RawLine), contentWidth-4)))

		formatted1 := hardTruncate(line1, contentWidth)
		formatted2 := hardTruncate(line2, contentWidth)
		padding1 := strings.Repeat(" ", max(0, contentWidth-lipgloss.Width(formatted1)))
		padding2 := strings.Repeat(" ", max(0, contentWidth-lipgloss.Width(formatted2)))

		if idx == m.selectedLogIndex && m.activeFocus == FocusLogs {
			lines = append(lines, styleSelected.Render(formatted1+padding1)+scrollChar)
			lines = append(lines, styleSelected.Render(formatted2+padding2)+scrollChar)
		} else {
			lines = append(lines, formatted1+padding1+scrollChar)
			lines = append(lines, formatted2+padding2+scrollChar)
		}
	}
	return lines
}

func renderMitreItem(techID, name string, count int) string {
	return fmt.Sprintf("%-10s %-22s %s",
		techID,
		safeText(name, 22),
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFC2")).Render(fmt.Sprintf("[%3d]", count)),
	)
}

func (m *SIEMModel) renderMITREPanel(width, maxLines int) string {
	var b strings.Builder
	b.WriteString(safeText(styleMatrixTitle.Render("🛡️ MITRE ATT&CK"), width) + "\n")
	b.WriteString(styleMuted.Render(strings.Repeat("─", max(2, width))) + "\n")

	colHeader := fmt.Sprintf("%-10s %-22s %s", styleMuted.Render("[ID]"), styleMuted.Render("[Technique Name]"), styleMuted.Render("[Hits]"))
	b.WriteString(safeText(colHeader, width) + "\n")

	linesWritten := 3
	analyzer := m.server.GetAnalyzer()

	var list []techniqueStat
	for k, v := range m.mitreMap {
		name, tactic := "", ""
		if analyzer != nil {
			name, tactic = analyzer.GetTechniqueMeta(k)
		}
		if name == "" {
			name = k
		}
		list = append(list, techniqueStat{ID: k, Name: name, Tactic: tactic, Count: v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count == list[j].Count {
			return list[i].ID < list[j].ID
		}
		return list[i].Count > list[j].Count
	})

	for _, st := range list {
		if linesWritten >= maxLines {
			break
		}

		color := colorCyberCyan
		if st.Count >= 20 {
			color = colorAlertPink
		} else if st.Count >= 5 {
			color = colorWarningGold
		}

		techStr := lipgloss.NewStyle().Bold(true).Foreground(color).Render(fmt.Sprintf("%-10s", st.ID))
		hitsBadge := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFC2")).Render(fmt.Sprintf("[%3d]", st.Count))
		nameLen := max(10, width-20)
		row := fmt.Sprintf("%s %-22s %s", techStr, styleLight.Render(safeText(st.Name, nameLen)), hitsBadge)
		b.WriteString(safeText(row, width) + "\n")
		linesWritten++
	}

	return b.String()
}

func (m *SIEMModel) renderThreatIntelPanel(width, maxLines int) string {
	var b strings.Builder
	b.WriteString(hardTruncate(styleWarning.Render("🌐 GEOGRAPHIC THREAT RADAR"), width) + "\n")
	b.WriteString(styleMuted.Render(strings.Repeat("─", max(2, width))) + "\n")

	var attackers []*attackerIntel
	for _, at := range m.attackerMap {
		attackers = append(attackers, at)
	}
	sort.Slice(attackers, func(i, j int) bool {
		return attackers[i].Count > attackers[j].Count
	})

	linesWritten := 2
	if len(attackers) == 0 {
		b.WriteString(hardTruncate(styleMuted.Render("No threat actors logged yet"), width))
	} else {
		for _, at := range attackers {
			if linesWritten >= maxLines {
				break
			}
			row1 := fmt.Sprintf("%s %-16s [%s]",
				at.Flag,
				styleAlert.Render(at.IP),
				styleGreen.Render(fmt.Sprintf("x%d", at.Count)))
			b.WriteString(hardTruncate(row1, width) + "\n")
			linesWritten++

			if linesWritten >= maxLines {
				break
			}
			row2 := fmt.Sprintf("   └ %s (%s)",
				styleCyan.Render(hardTruncate(at.Org, 16)),
				styleWarning.Render(hardTruncate(at.Class, 12)))
			b.WriteString(hardTruncate(row2, width) + "\n")
			linesWritten++
		}
	}

	return b.String()
}

func (m *SIEMModel) renderFooterBar() string {
	leftHelp := "[Tab] Focus | [1-6] Tabs | [↑/↓] Move | [Enter] Select | [B] Ban | [U] Unban | [Esc] Clear | [Q] Quit"

	var activeTabName string
	switch m.activeLogTab {
	case TabIncidents:
		activeTabName = "INCIDENTS"
	case TabAll:
		activeTabName = "ALL"
	case TabNginx:
		activeTabName = "NGINX"
	case TabAuth:
		activeTabName = "AUTH"
	case TabSuricata:
		activeTabName = "SURICATA"
	case TabAuditSyslog:
		activeTabName = "AUDIT"
	default:
		activeTabName = "STREAM"
	}

	rightStatus := fmt.Sprintf("EPS: %d | Threats: %d | Tab: %s", m.server.GetEPS(), len(m.incidents), activeTabName)

	gap := m.width - lipgloss.Width(leftHelp) - lipgloss.Width(rightStatus) - 2
	if gap < 1 {
		gap = 1
	}

	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#64748B")).
		Render(leftHelp + strings.Repeat(" ", gap) + rightStatus)
}

func (m *SIEMModel) renderBottomPanel(width int) string {
	return m.renderFooterBar()
}

func (m *SIEMModel) renderSearchModalOverlay() string {
	title := "🔍 THREAT HUNTING SEARCH MATRIX"
	prompt := "Syntax: ip:1.2.3.4  |  mitre:T1190  |  score:>70  |  src:nginx  |  q:keyword"

	content := fmt.Sprintf("%s\n\n%s\n\n> %s█\n\n%s",
		styleHeader.Render(title),
		styleMuted.Render(prompt),
		styleGreen.Render(cleanForTerminal(m.inputSearch)),
		styleMuted.Render("[Enter] Execute Query   [Esc] Cancel / Clear Filter"),
	)

	return renderModal(content, m.width, m.height)
}

func (m *SIEMModel) renderModalOverlay() string {
	title := "🚫 EXECUTE GLOBAL FLEET BAN"
	prompt := "Enter Target IP address to ban across all nodes:"
	if m.mode == modalUnbanIP {
		title = "🔓 EXECUTE GLOBAL FLEET UNBAN"
		prompt = "Enter Target IP address to unban:"
	}

	content := fmt.Sprintf("%s\n\n%s\n\n> %s█\n\n%s",
		styleAlert.Render(title),
		styleLight.Render(prompt),
		styleCyan.Render(cleanForTerminal(m.inputIP)),
		styleMuted.Render("[Enter] Confirm Action   [Esc] Cancel"),
	)

	return renderModal(content, m.width, m.height)
}

func (m *SIEMModel) renderInspectionModal() string {
	ev := m.inspectEvent
	if ev == nil {
		m.mode = modalNone
		return m.View()
	}

	analyzer := m.server.GetAnalyzer()
	techName, tactic := "", ""
	if analyzer != nil {
		techName, tactic = analyzer.GetTechniqueMeta(ev.MitreTechniqueID)
	}

	scoreLabel := fmt.Sprintf("[%d]", ev.ThreatScore)
	if ev.ThreatScore >= 80 {
		scoreLabel = fmt.Sprintf("[CRITICAL %d]", ev.ThreatScore)
	} else if ev.ThreatScore >= 50 {
		scoreLabel = fmt.Sprintf("[WARNING %d]", ev.ThreatScore)
	}

	sourceLabel := "HTTP (Nginx)"
	switch ev.Source {
	case "auth", "ssh":
		sourceLabel = "AUTH (SSH)"
	case "suricata":
		sourceLabel = "IDS (Suricata EVE)"
	case "audit":
		sourceLabel = "KERNEL (Linux Auditd)"
	case "syslog":
		sourceLabel = "SYS (Linux Syslog)"
	}

	timeStr := time.UnixMilli(ev.TimestampMs).UTC().Format("2006-01-02 15:04:05 UTC")
	decodedPayload := cleanForTerminal(NormalizePayload(ev.RawLine))

	aiIntelText := "No anomalies requiring deep LLM analysis detected."
	if ev.AIAnalysis != "" {
		aiIntelText = cleanForTerminal(ev.AIAnalysis)
	} else if ev.ThreatScore >= 80 {
		aiIntelText = fmt.Sprintf("Critical exploit attempt matched signature '%s'. Recommended action: Global Fleet Ban.", cleanForTerminal(ev.RuleID))
	}

	content := fmt.Sprintf("🔍 %s\n\n"+
		"🕒 Timestamp:    %s\n"+
		"🌐 Node ID:      %s\n"+
		"🎯 Source:       %s\n"+
		"🚨 Threat Score: %s\n"+
		"🛡 MITRE Tactic: %s\n"+
		"🏷 Technique:    %s - %s\n"+
		"👤 Attacker IP:  %s\n\n"+
		"📜 %s:\n"+
		"%s\n\n"+
		"🧠 %s:\n"+
		"%s\n\n"+
		"%s",
		styleHeader.Render("FORENSIC INCIDENT INSPECTION"),
		styleLight.Render(timeStr),
		styleGreen.Render(cleanForTerminal(ev.NodeID)),
		styleCyan.Render(sourceLabel),
		styleAlert.Render(scoreLabel),
		styleWarning.Render(tactic),
		styleCyan.Render(ev.MitreTechniqueID),
		techName,
		styleAlert.Render(cleanForTerminal(ev.ClientIP)),
		styleWarning.Render("DECODED & SANITIZED PAYLOAD"),
		styleLight.Render(decodedPayload),
		styleGreen.Render("AI INTEL & INTENT"),
		styleMuted.Render(aiIntelText),
		styleMuted.Render("[Esc / Enter] Close Inspection Modal"),
	)

	return renderModal(content, m.width, m.height)
}
