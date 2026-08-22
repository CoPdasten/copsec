package main

import (
	"fmt"
	"sort"
	"strconv"
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
			BorderForeground(colorPanelBorder).
			Padding(0, 1)

	styleActivePanel = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorCyberCyan).
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
			Padding(1, 2).
			Width(68)

	styleSearchBox = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(colorCyberCyan).
			Padding(1, 2).
			Width(72)

	styleInspectionCard = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorCyberCyan).
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

	// Viewport Scroll & Cursor State
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

// NewSIEMModel creates a high-performance strictly-bounded 6-panel TUI model.
func NewSIEMModel(server *CentralServer, storage *StorageEngine) *SIEMModel {
	m := &SIEMModel{
		server:          server,
		storage:         storage,
		activeTab:       1,
		mitreMap:        make(map[string]int),
		attackerMap:     make(map[string]*attackerIntel),
		targetMap:       make(map[string]int),
		killChainHits:   make(map[string]int),
		rateHistory:     make([]int, 20),
		recentEntropies: make([]float64, 0, 30),
		events:          make([]*StoredEvent, 0, 250),
		incidents:       make([]*StoredEvent, 0, 120),
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
	if incs, err := storage.GetCriticalEvents(40); err == nil {
		m.incidents = incs
	}
	if bans, err := storage.GetActiveBans(); err == nil {
		m.activeBans = bans
	}
	if actions, err := storage.GetRecentSOARActions(5); err == nil {
		m.soarActions = actions
	}

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

// hardTruncate cuts line cleanly without causing line-wrapping.
func hardTruncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}

func (m *SIEMModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case *StoredEvent:
		m.processIncomingEvent(msg)
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
		case "tab":
			m.activeTab = (m.activeTab + 1) % 4
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
				m.statusPrompt = "🔍 Filter cleared"
			}
		case "up", "k":
			if m.activeTab == 2 {
				if m.selectedIncIndex > 0 {
					m.selectedIncIndex--
					if m.selectedIncIndex < m.incScrollOffset {
						m.incScrollOffset = m.selectedIncIndex
					}
				}
			} else {
				if m.selectedLogIndex > 0 {
					m.selectedLogIndex--
					if m.selectedLogIndex < m.logScrollOffset {
						m.logScrollOffset = m.selectedLogIndex
					}
				}
			}
		case "down", "j":
			if m.activeTab == 2 {
				if m.selectedIncIndex < len(m.incidents)-1 {
					m.selectedIncIndex++
				}
			} else {
				currentList := m.getCurrentEventsList()
				if m.selectedLogIndex < len(currentList)-1 {
					m.selectedLogIndex++
				}
			}
		case "pgup", "ctrl+u":
			if m.activeTab == 2 {
				m.selectedIncIndex = max(0, m.selectedIncIndex-5)
				m.incScrollOffset = max(0, m.incScrollOffset-5)
			} else {
				m.selectedLogIndex = max(0, m.selectedLogIndex-5)
				m.logScrollOffset = max(0, m.logScrollOffset-5)
			}
		case "pgdown", "ctrl+d":
			if m.activeTab == 2 {
				m.selectedIncIndex = min(len(m.incidents)-1, m.selectedIncIndex+5)
			} else {
				currentList := m.getCurrentEventsList()
				m.selectedLogIndex = min(len(currentList)-1, m.selectedLogIndex+5)
			}
		case "enter":
			if m.activeTab == 2 && len(m.incidents) > 0 && m.selectedIncIndex < len(m.incidents) {
				m.inspectEvent = m.incidents[m.selectedIncIndex]
				m.mode = modalLogDetail
			} else {
				currentList := m.getCurrentEventsList()
				if len(currentList) > 0 && m.selectedLogIndex < len(currentList) {
					m.inspectEvent = currentList[m.selectedLogIndex]
					m.mode = modalLogDetail
				}
			}
		case " ":
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
		m.mu.Lock()
		if len(m.eventBuffer) > 0 {
			for _, ev := range m.eventBuffer {
				m.processIncomingEvent(ev)
			}
			m.eventBuffer = nil
		}
		m.mu.Unlock()

		m.nodes = m.server.GetNodesSnapshot()
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
	if ev.ThreatScore >= 50 {
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
	if m.isFilterActive {
		return m.filteredEvents
	}
	return m.events
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

func (m *SIEMModel) View() string {
	if m.width == 0 {
		return "Initializing CoPSeC Enterprise Cyber-Defense Cockpit..."
	}

	// 1. Column Width Calculations (24% Left, 46% Center, 30% Right)
	leftWidth := int(float64(m.width) * 0.24)
	if leftWidth < 28 {
		leftWidth = 28
	}

	rightWidth := int(float64(m.width) * 0.30)
	if rightWidth < 36 {
		rightWidth = 36
	}

	centerWidth := m.width - leftWidth - rightWidth - 6
	if centerWidth < 30 {
		centerWidth = 30
	}

	// 2. Strict Row Height Calculations (Budget: 1 line header + mainGrid + 1 line bottom = m.height)
	mainHeight := m.height - 2
	if mainHeight < 14 {
		mainHeight = 14
	}

	topHeight := mainHeight / 2
	bottomHeight := mainHeight - topHeight

	// Inner body height available per box (excluding top/bottom border lines)
	innerTopHeight := topHeight - 2
	innerBottomHeight := bottomHeight - 2
	if innerTopHeight < 2 {
		innerTopHeight = 2
	}
	if innerBottomHeight < 2 {
		innerBottomHeight = 2
	}

	// 3. Left Column: Fleet Matrix + SOAR Jail
	leftTopStyle := styleBasePanel
	if m.activeTab == 0 {
		leftTopStyle = styleActivePanel
	}
	leftTopBody := fitLines(m.renderFleetPanel(leftWidth-4, innerTopHeight), innerTopHeight)
	leftTopPanel := leftTopStyle.Width(leftWidth).Height(topHeight).MaxHeight(topHeight).MaxWidth(leftWidth).Render(leftTopBody)

	leftBottomBody := fitLines(m.renderJailPanel(leftWidth-4, innerBottomHeight), innerBottomHeight)
	leftBottomPanel := styleBasePanel.Width(leftWidth).Height(bottomHeight).MaxHeight(bottomHeight).MaxWidth(leftWidth).Render(leftBottomBody)
	leftColumn := lipgloss.JoinVertical(lipgloss.Left, leftTopPanel, leftBottomPanel)

	// 4. Center Column: Live Stream + Critical Incidents
	topStyle := styleBasePanel
	if m.activeTab == 1 {
		topStyle = styleActivePanel
	}
	centerTopBody := fitLines(m.renderThreatStream(centerWidth-4, innerTopHeight), innerTopHeight)
	centerTopPanel := topStyle.Width(centerWidth).Height(topHeight).MaxHeight(topHeight).MaxWidth(centerWidth).Render(centerTopBody)

	bottomStyle := styleBasePanel
	if m.activeTab == 2 {
		bottomStyle = styleActivePanel
	}
	centerBottomBody := fitLines(m.renderIncidentStream(centerWidth-4, innerBottomHeight), innerBottomHeight)
	centerBottomPanel := bottomStyle.Width(centerWidth).Height(bottomHeight).MaxHeight(bottomHeight).MaxWidth(centerWidth).Render(centerBottomBody)
	centerColumn := lipgloss.JoinVertical(lipgloss.Left, centerTopPanel, centerBottomPanel)

	// 5. Right Column: Enterprise MITRE + Geo Threat Radar
	rightTopStyle := styleBasePanel
	if m.activeTab == 3 {
		rightTopStyle = styleActivePanel
	}
	rightTopBody := fitLines(m.renderMITREPanel(rightWidth-4, innerTopHeight), innerTopHeight)
	rightTopPanel := rightTopStyle.Width(rightWidth).Height(topHeight).MaxHeight(topHeight).MaxWidth(rightWidth).Render(rightTopBody)

	rightBottomBody := fitLines(m.renderThreatIntelPanel(rightWidth-4, innerBottomHeight), innerBottomHeight)
	rightBottomPanel := styleBasePanel.Width(rightWidth).Height(bottomHeight).MaxHeight(bottomHeight).MaxWidth(rightWidth).Render(rightBottomBody)
	rightColumn := lipgloss.JoinVertical(lipgloss.Left, rightTopPanel, rightBottomPanel)

	// 6. Horizontal Main Grid Join
	mainGrid := lipgloss.JoinHorizontal(lipgloss.Top, leftColumn, centerColumn, rightColumn)

	// 7. Single Bottom Bar Render
	bottom := m.renderBottomPanel(m.width)

	// 8. Clean Join
	baseView := lipgloss.JoinVertical(lipgloss.Left, mainGrid, bottom)

	if m.mode == modalLogDetail {
		return m.renderInspectionModal(baseView)
	} else if m.mode == modalSearch {
		return m.renderSearchModalOverlay(baseView)
	} else if m.mode != modalNone {
		return m.renderModalOverlay(baseView)
	}

	return baseView
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
	b.WriteString(hardTruncate(styleMatrixTitle.Render("🌐 FLEET MATRIX & TELEMETRY"), width) + "\n")
	b.WriteString(styleMuted.Render(strings.Repeat("─", max(2, width))) + "\n")

	if len(m.nodes) == 0 {
		b.WriteString(hardTruncate(styleMuted.Render("No edge nodes connected."), width) + "\n")
		b.WriteString(hardTruncate(styleMuted.Render("(gRPC 0.0.0.0:8443)"), width))
		return b.String()
	}

	linesWritten := 2
	for _, n := range m.nodes {
		if linesWritten >= maxLines {
			break
		}
		isOnline := time.Since(n.LastSeen) <= 20*time.Second
		statusBadge := styleGreen.Render("🟢")
		if !isOnline {
			statusBadge = styleAlert.Render("🔴")
		}

		nodeName := hardTruncate(n.NodeID, max(4, width-3))
		cpuBar := renderMiniBar(n.CPUUsage, 5)
		ramBar := renderMiniBar(n.MemoryUsage/256.0*100.0, 5)

		row1 := fmt.Sprintf("%s %s", statusBadge, lipgloss.NewStyle().Bold(true).Foreground(colorCyberCyan).Render(nodeName))
		b.WriteString(hardTruncate(row1, width) + "\n")
		linesWritten++
		if linesWritten >= maxLines {
			break
		}

		row2 := fmt.Sprintf(" CPU:[%s]%0.0f%% RAM:[%s]%0.0fM",
			styleGreen.Render(cpuBar), n.CPUUsage,
			styleCyan.Render(ramBar), n.MemoryUsage)
		b.WriteString(hardTruncate(row2, width) + "\n")
		linesWritten++
		if linesWritten >= maxLines {
			break
		}

		row3 := fmt.Sprintf(" 🛡️ Bans:%d | Ping:~12ms | Buff:OK", n.ActiveBansCount)
		b.WriteString(hardTruncate(row3, width) + "\n")
		linesWritten++
	}
	return b.String()
}

func (m *SIEMModel) renderJailPanel(width, maxLines int) string {
	var b strings.Builder
	b.WriteString(hardTruncate(styleAlert.Render("🛡 SOAR JAIL & MITIGATIONS"), width) + "\n")
	b.WriteString(styleMuted.Render(strings.Repeat("─", max(2, width))) + "\n")

	linesWritten := 2
	if len(m.activeBans) == 0 {
		b.WriteString(hardTruncate(styleMuted.Render("No active IP isolations."), width) + "\n")
		b.WriteString(hardTruncate(styleMuted.Render("Perimeter defense idle."), width) + "\n")
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
			if len(reason) > 12 {
				reason = reason[:12]
			}

			line := fmt.Sprintf("🚫 %-15s %s %s", hardTruncate(ban.IP, 15), styleWarning.Render(reason), remStr)
			b.WriteString(hardTruncate(line, width) + "\n")
			linesWritten++
		}
	}

	if linesWritten < maxLines && len(m.soarActions) > 0 {
		act := m.soarActions[0]
		ackLine := fmt.Sprintf("[ACK] %s %s (%dn)", act.ActionType, hardTruncate(act.TargetIP, 14), act.NodesCount)
		b.WriteString(hardTruncate(styleGreen.Render(ackLine), width))
	}
	return b.String()
}

func (m *SIEMModel) renderThreatStream(width, maxLines int) string {
	var b strings.Builder
	eps := m.server.GetEPS()
	pauseTag := ""
	if m.isPaused {
		pauseTag = " [PAUSED]"
	}

	var spark strings.Builder
	for _, val := range m.rateHistory[len(m.rateHistory)-6:] {
		if val == 0 {
			spark.WriteString(" ")
		} else if val < 10 {
			spark.WriteString("▃")
		} else if val < 50 {
			spark.WriteString("▅")
		} else {
			spark.WriteString("█")
		}
	}

	entBadge := fmt.Sprintf("Ent:%0.2fb", m.avgEntropy)
	if m.avgEntropy > 5.0 {
		entBadge = styleAlert.Render(fmt.Sprintf("Ent:%0.2fb", m.avgEntropy))
	} else {
		entBadge = styleCyan.Render(entBadge)
	}

	currentList := m.getCurrentEventsList()
	title := "⚡ LIVE STREAM"
	if m.isFilterActive {
		title = fmt.Sprintf("🔍 FILTER: [%s]", hardTruncate(m.searchQuery, 10))
	}

	header := fmt.Sprintf("%s %s [%s|Pk:%d|%s]%s",
		styleHeader.Render(title),
		styleGreen.Render(spark.String()),
		styleGreen.Render(fmt.Sprintf("EPS:%d", eps)),
		m.peakEPS,
		entBadge,
		styleAlert.Render(pauseTag))
	b.WriteString(hardTruncate(header, width) + "\n")
	b.WriteString(styleMuted.Render(strings.Repeat("─", max(2, width))) + "\n")

	if len(currentList) == 0 {
		if m.isFilterActive {
			b.WriteString(hardTruncate(styleWarning.Render("No entries match query filter. [Esc] to Clear."), width))
		} else {
			b.WriteString(hardTruncate(styleMuted.Render("Listening for edge node stream events..."), width))
		}
		return b.String()
	}

	availableLines := maxLines - 2
	visibleItems := availableLines / 2
	if visibleItems <= 0 {
		visibleItems = 1
	}

	if m.selectedLogIndex < m.logScrollOffset {
		m.logScrollOffset = m.selectedLogIndex
	} else if m.selectedLogIndex >= m.logScrollOffset+visibleItems {
		m.logScrollOffset = m.selectedLogIndex - visibleItems + 1
	}

	for i := 0; i < visibleItems; i++ {
		idx := m.logScrollOffset + i
		if idx >= len(currentList) {
			break
		}

		ev := currentList[idx]
		timeStr := time.UnixMilli(ev.TimestampMs).Format("15:04:05")
		srcIcon := "🌐 HTTP"
		if ev.Source == "ssh" {
			srcIcon = "🔑 AUTH"
		} else if ev.Source == "syslog" {
			srcIcon = "⚡ SYS"
		}

		scoreBadge := styleGreen.Render(fmt.Sprintf("[%d]", ev.ThreatScore))
		if ev.ThreatScore >= 80 {
			scoreBadge = styleAlert.Render(fmt.Sprintf("[%d]", ev.ThreatScore))
		} else if ev.ThreatScore >= 50 {
			scoreBadge = styleWarning.Render(fmt.Sprintf("[%d]", ev.ThreatScore))
		}

		prefix := "  "
		if m.activeTab == 1 && idx == m.selectedLogIndex {
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
		line1 := fmt.Sprintf("%s%s %s %s 🎯 %s 🏷 %s",
			prefix,
			styleMuted.Render(timeStr),
			scoreBadge,
			styleCyan.Render(srcIcon),
			lipgloss.NewStyle().Bold(true).Foreground(colorTextLight).Render(ev.ClientIP),
			styleWarning.Render(ev.MitreTechniqueID),
		)
		line2 := fmt.Sprintf("    %s", styleMuted.Render(hardTruncate(ev.RawLine, contentWidth-4)))

		formatted1 := hardTruncate(line1, contentWidth)
		formatted2 := hardTruncate(line2, contentWidth)
		padding1 := strings.Repeat(" ", max(0, contentWidth-lipgloss.Width(formatted1)))
		padding2 := strings.Repeat(" ", max(0, contentWidth-lipgloss.Width(formatted2)))

		if m.activeTab == 1 && idx == m.selectedLogIndex {
			b.WriteString(styleSelected.Render(formatted1+padding1) + scrollChar + "\n")
			b.WriteString(styleSelected.Render(formatted2+padding2) + scrollChar + "\n")
		} else {
			b.WriteString(formatted1 + padding1 + scrollChar + "\n")
			b.WriteString(formatted2 + padding2 + scrollChar + "\n")
		}
	}
	return b.String()
}

func (m *SIEMModel) renderIncidentStream(width, maxLines int) string {
	var b strings.Builder
	b.WriteString(hardTruncate(styleAlert.Render("🔥 CRITICAL INCIDENTS (THREAT >= 50)"), width) + "\n")
	b.WriteString(styleMuted.Render(strings.Repeat("─", max(2, width))) + "\n")

	if len(m.incidents) == 0 {
		b.WriteString(hardTruncate(styleMuted.Render("No critical incidents logged. Threat perimeter secure."), width))
		return b.String()
	}

	availableLines := maxLines - 2
	visibleItems := availableLines / 2
	if visibleItems <= 0 {
		visibleItems = 1
	}

	if m.selectedIncIndex < m.incScrollOffset {
		m.incScrollOffset = m.selectedIncIndex
	} else if m.selectedIncIndex >= m.incScrollOffset+visibleItems {
		m.incScrollOffset = m.selectedIncIndex - visibleItems + 1
	}

	for i := 0; i < visibleItems; i++ {
		idx := m.incScrollOffset + i
		if idx >= len(m.incidents) {
			break
		}

		ev := m.incidents[idx]
		timeStr := time.UnixMilli(ev.TimestampMs).Format("15:04:05")
		scoreBadge := styleAlert.Render(fmt.Sprintf("[%d]", ev.ThreatScore))
		if ev.ThreatScore < 70 {
			scoreBadge = styleWarning.Render(fmt.Sprintf("[%d]", ev.ThreatScore))
		}

		prefix := "  "
		if m.activeTab == 2 && idx == m.selectedIncIndex {
			prefix = "▶ "
		}

		scrollChar := styleScrollTrack.Render("│")
		if len(m.incidents) > 1 && visibleItems > 1 {
			thumbPos := int(float64(m.selectedIncIndex) / float64(len(m.incidents)-1) * float64(visibleItems-1))
			if i == thumbPos {
				scrollChar = styleAlert.Render("█")
			}
		}

		contentWidth := max(10, width-2)
		line1 := fmt.Sprintf("%s%s %s 🎯 %s 🏷 %s (%s)",
			prefix,
			styleMuted.Render(timeStr),
			scoreBadge,
			lipgloss.NewStyle().Bold(true).Foreground(colorAlertPink).Render(ev.ClientIP),
			styleWarning.Render(ev.MitreTechniqueID),
			styleCyan.Render(hardTruncate(ev.RuleID, 12)),
		)
		line2 := fmt.Sprintf("    %s", styleLight.Render(hardTruncate(ev.RawLine, contentWidth-4)))

		formatted1 := hardTruncate(line1, contentWidth)
		formatted2 := hardTruncate(line2, contentWidth)
		padding1 := strings.Repeat(" ", max(0, contentWidth-lipgloss.Width(formatted1)))
		padding2 := strings.Repeat(" ", max(0, contentWidth-lipgloss.Width(formatted2)))

		if m.activeTab == 2 && idx == m.selectedIncIndex {
			b.WriteString(styleSelected.Render(formatted1+padding1) + scrollChar + "\n")
			b.WriteString(styleSelected.Render(formatted2+padding2) + scrollChar + "\n")
		} else {
			b.WriteString(formatted1 + padding1 + scrollChar + "\n")
			b.WriteString(formatted2 + padding2 + scrollChar + "\n")
		}
	}
	return b.String()
}

func (m *SIEMModel) renderMITREPanel(width, maxLines int) string {
	var b strings.Builder
	b.WriteString(hardTruncate(styleMatrixTitle.Render("🛡 ENTERPRISE MITRE INTEL"), width) + "\n")
	b.WriteString(styleMuted.Render(strings.Repeat("─", max(2, width))) + "\n")

	renderKillStage := func(name string, hits int) string {
		if hits > 0 {
			return fmt.Sprintf("[%s%s]", name, styleAlert.Render("█"))
		}
		return fmt.Sprintf("[%s%s]", name, styleMuted.Render("░"))
	}
	killChainStr := fmt.Sprintf("%s➔%s➔%s➔%s➔%s",
		renderKillStage("Rec", m.killChainHits["Recon"]),
		renderKillStage("Ini", m.killChainHits["Initial"]),
		renderKillStage("Exe", m.killChainHits["Execution"]),
		renderKillStage("Per", m.killChainHits["Persist"]),
		renderKillStage("Exf", m.killChainHits["Exfil"]),
	)
	b.WriteString(hardTruncate(killChainStr, width) + "\n")

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

		barLen := 0
		if st.Count > 0 {
			barLen = min(st.Count/2+1, 5)
		}
		filled := strings.Repeat("█", barLen)
		empty := strings.Repeat("░", 5-barLen)

		techName := st.Name
		if len(techName) > 15 {
			techName = techName[:15]
		}

		color := colorCyberCyan
		if st.Count >= 20 {
			color = colorAlertPink
		} else if st.Count >= 5 {
			color = colorWarningGold
		}

		row := fmt.Sprintf("%-6s %-15s %s%s %2d",
			lipgloss.NewStyle().Bold(true).Foreground(color).Render(st.ID),
			styleLight.Render(techName),
			styleAlert.Render(filled),
			lipgloss.NewStyle().Foreground(colorPanelBorder).Render(empty),
			st.Count)
		b.WriteString(hardTruncate(row, width) + "\n")
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
			row1 := fmt.Sprintf("%s %-16s [%s Hits]",
				at.Flag,
				styleAlert.Render(at.IP),
				styleGreen.Render(strconv.Itoa(at.Count)))
			b.WriteString(hardTruncate(row1, width) + "\n")
			linesWritten++

			if linesWritten >= maxLines {
				break
			}
			row2 := fmt.Sprintf("   └ %s / %s 🎯 %s",
				styleCyan.Render(hardTruncate(at.Org, 14)),
				styleWarning.Render(hardTruncate(at.Class, 10)),
				styleMuted.Render(at.TopTarget))
			b.WriteString(hardTruncate(row2, width) + "\n")
			linesWritten++
		}
	}

	return b.String()
}

func (m *SIEMModel) renderBottomPanel(width int) string {
	eps := m.server.GetEPS()
	threats := len(m.incidents)

	bottomText := fmt.Sprintf(" [/] Search  [B] Ban  [U] Unban  [Space] Pause  [Tab] Focus  [Enter] Inspect  [Q] Quit    |  EPS: %d  Peak: %d  Threats: %d",
		eps, m.peakEPS, threats)

	if m.statusPrompt != "" {
		bottomText += fmt.Sprintf("  |  %s", m.statusPrompt)
	}

	return lipgloss.NewStyle().
		Width(width).
		Background(lipgloss.Color("#11111b")).
		Foreground(lipgloss.Color("#a6adc8")).
		Render(bottomText)
}

func (m *SIEMModel) renderSearchModalOverlay(baseView string) string {
	title := "🔍 THREAT HUNTING SEARCH MATRIX"
	prompt := "Syntax: ip:1.2.3.4  |  mitre:T1190  |  score:>70  |  src:nginx  |  q:keyword"

	content := fmt.Sprintf("%s\n\n%s\n\n> %s█\n\n%s",
		styleHeader.Render(title),
		styleMuted.Render(prompt),
		styleGreen.Render(m.inputSearch),
		styleMuted.Render("[Enter] Execute Query   [Esc] Cancel / Clear Filter"),
	)

	modalBox := styleSearchBox.Render(content)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modalBox,
		lipgloss.WithWhitespaceChars(" "),
		lipgloss.WithWhitespaceForeground(colorDarkBg),
	)
}

func (m *SIEMModel) renderModalOverlay(baseView string) string {
	title := "🚫 EXECUTE GLOBAL FLEET BAN"
	prompt := "Enter Target IP address to ban across all nodes:"
	if m.mode == modalUnbanIP {
		title = "🔓 EXECUTE GLOBAL FLEET UNBAN"
		prompt = "Enter Target IP address to unban:"
	}

	content := fmt.Sprintf("%s\n\n%s\n\n> %s█\n\n%s",
		styleAlert.Render(title),
		styleLight.Render(prompt),
		styleCyan.Render(m.inputIP),
		styleMuted.Render("[Enter] Confirm Action   [Esc] Cancel"),
	)

	modalBox := styleModalBox.Render(content)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modalBox,
		lipgloss.WithWhitespaceChars(" "),
		lipgloss.WithWhitespaceForeground(colorDarkBg),
	)
}

func (m *SIEMModel) renderInspectionModal(baseView string) string {
	ev := m.inspectEvent
	if ev == nil {
		m.mode = modalNone
		return baseView
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
	if ev.Source == "ssh" {
		sourceLabel = "AUTH (SSH)"
	} else if ev.Source == "syslog" {
		sourceLabel = "SYS (Linux)"
	}

	timeStr := time.UnixMilli(ev.TimestampMs).UTC().Format("2006-01-02 15:04:05 UTC")
	decodedPayload := NormalizePayload(ev.RawLine)

	aiIntelText := "No anomalies requiring deep LLM analysis detected."
	if ev.AIAnalysis != "" {
		aiIntelText = ev.AIAnalysis
	} else if ev.ThreatScore >= 80 {
		aiIntelText = fmt.Sprintf("Critical exploit attempt matched signature '%s'. Recommended action: Global Fleet Ban.", ev.RuleID)
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
		styleGreen.Render(ev.NodeID),
		styleCyan.Render(sourceLabel),
		styleAlert.Render(scoreLabel),
		styleWarning.Render(tactic),
		styleCyan.Render(ev.MitreTechniqueID),
		techName,
		styleAlert.Render(ev.ClientIP),
		styleWarning.Render("DECODED PAYLOAD"),
		styleLight.Render(decodedPayload),
		styleGreen.Render("AI INTEL & INTENT"),
		styleMuted.Render(aiIntelText),
		styleMuted.Render("[Esc / Enter] Close Inspection Modal"),
	)

	card := styleInspectionCard.Render(content)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, card,
		lipgloss.WithWhitespaceChars(" "),
		lipgloss.WithWhitespaceForeground(colorDarkBg),
	)
}
