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

// Cyberpunk / Matrix Color Palette
var (
	colorNeonGreen   = lipgloss.Color("#00FF66")
	colorCyberCyan   = lipgloss.Color("#00F0FF")
	colorAlertPink   = lipgloss.Color("#FF0055")
	colorWarningGold = lipgloss.Color("#FFB800")
	colorDarkBg      = lipgloss.Color("#0A0E14")
	colorPanelBorder = lipgloss.Color("#1E293B")
	colorTextMuted   = lipgloss.Color("#64748B")
	colorTextLight   = lipgloss.Color("#E2E8F0")
	colorSelectedBg  = lipgloss.Color("#1A2333")

	// Panel Styles
	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorPanelBorder).
			Padding(0, 1)

	activePanelStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorCyberCyan).
				Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorCyberCyan)

	matrixTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorNeonGreen)

	alertStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAlertPink)

	modalBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(colorAlertPink).
			Padding(1, 2).
			Width(68)

	searchBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(colorCyberCyan).
			Padding(1, 2).
			Width(72)

	detailBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(colorCyberCyan).
			Padding(1, 2).
			Width(76)
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

type attackerStat struct {
	IP    string
	Count int
}

// SIEMModel holds the state for the dual-window SOC cockpit with search & forensic inspection.
type SIEMModel struct {
	server       *CentralServer
	storage      *StorageEngine
	width        int
	height       int
	events       []*StoredEvent
	incidents    []*StoredEvent
	nodes        []NodeSession
	mitreMap     map[string]int
	attackerMap  map[string]int
	activeTab    int
	rateHistory  []int
	statusPrompt string
	isPaused     bool

	// Threat Hunting Search
	searchQuery   string
	isFilterActive bool
	inputSearch   string

	// Navigation
	selectedLogIndex int
	selectedIncIndex int

	// Async event queue buffer
	mu          sync.Mutex
	eventBuffer []*StoredEvent

	// Modal State
	mode    modalMode
	inputIP string
}

// NewSIEMModel creates a new TUI dashboard model with dual-window layout.
func NewSIEMModel(server *CentralServer, storage *StorageEngine) *SIEMModel {
	m := &SIEMModel{
		server:      server,
		storage:     storage,
		mitreMap:    make(map[string]int),
		attackerMap: make(map[string]int),
		rateHistory: make([]int, 25),
	}

	// Initialize default core techniques
	defaultCore := []string{"T1190", "T1059.004", "T1203", "T1078", "T1053.003", "T1548.001", "T1027", "T1070.003", "T1562.001", "T1110.001", "T1003.008", "T1552.001", "T1595.002", "T1082", "T1087.001", "T1046", "T1071.001", "T1041", "T1567"}
	for _, t := range defaultCore {
		m.mitreMap[t] = 0
	}

	// Load historical stats and incidents from DB
	if stats, err := storage.GetMITREStats(); err == nil {
		for _, s := range stats {
			m.mitreMap[s.TechniqueID] = s.Count
		}
	}
	if incs, err := storage.GetCriticalEvents(20); err == nil {
		m.incidents = incs
	}

	// Background worker reading events into memory buffer
	go func() {
		sub := server.SubscribeEvents()
		for ev := range sub {
			m.mu.Lock()
			m.eventBuffer = append(m.eventBuffer, ev)
			if len(m.eventBuffer) > 3000 {
				m.eventBuffer = m.eventBuffer[1500:]
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
	return tea.Tick(80*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *SIEMModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		// Modal interaction
		if m.mode != modalNone {
			switch msg.String() {
			case "esc":
				if m.mode == modalSearch && m.isFilterActive {
					m.isFilterActive = false
					m.searchQuery = ""
					m.statusPrompt = "🔍 Search filter cleared"
				}
				m.mode = modalNone
				m.inputIP = ""
				m.inputSearch = ""
				return m, nil
			case "enter":
				if m.mode == modalLogDetail {
					m.mode = modalNone
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

		// Normal navigation & shortcuts
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
				m.statusPrompt = "🔍 Search filter cleared. Resumed live stream."
			}
		case "up", "k":
			if m.activeTab == 1 { // Live Stream
				if m.selectedLogIndex > 0 {
					m.selectedLogIndex--
				}
			} else if m.activeTab == 2 { // Critical Incidents
				if m.selectedIncIndex > 0 {
					m.selectedIncIndex--
				}
			}
		case "down", "j":
			if m.activeTab == 1 {
				if m.selectedLogIndex < len(m.events)-1 && m.selectedLogIndex < 15 {
					m.selectedLogIndex++
				}
			} else if m.activeTab == 2 {
				if m.selectedIncIndex < len(m.incidents)-1 && m.selectedIncIndex < 15 {
					m.selectedIncIndex++
				}
			}
		case "enter":
			if m.activeTab == 2 && len(m.incidents) > 0 && m.selectedIncIndex < len(m.incidents) {
				m.mode = modalLogDetail
			} else if len(m.events) > 0 && m.selectedLogIndex < len(m.events) {
				m.mode = modalLogDetail
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
		// Drain in-memory event buffer in batch without blocking UI loop
		m.mu.Lock()
		if len(m.eventBuffer) > 0 {
			for _, ev := range m.eventBuffer {
				if !m.isPaused && !m.isFilterActive {
					m.events = append([]*StoredEvent{ev}, m.events...)
				}
				if ev.ThreatScore >= 50 {
					m.incidents = append([]*StoredEvent{ev}, m.incidents...)
					if len(m.incidents) > 40 {
						m.incidents = m.incidents[:40]
					}
				}
				if ev.MitreTechniqueID != "" {
					m.mitreMap[ev.MitreTechniqueID]++
				}
				if ev.ClientIP != "" && ev.ClientIP != "127.0.0.1" {
					m.attackerMap[ev.ClientIP]++
				}
			}
			m.eventBuffer = nil
			if len(m.events) > 80 {
				m.events = m.events[:80]
			}
		}
		m.mu.Unlock()

		m.nodes = m.server.GetNodesSnapshot()

		eps := int(m.server.GetEPS())
		m.rateHistory = append(m.rateHistory[1:], eps)

		return m, m.tickCmd()
	}

	return m, nil
}

func (m *SIEMModel) executeSearch() {
	query := strings.TrimSpace(m.inputSearch)
	m.mode = modalNone
	if query == "" {
		m.isFilterActive = false
		m.searchQuery = ""
		return
	}

	results, err := m.storage.SearchEvents(query, 50)
	if err != nil {
		m.statusPrompt = fmt.Sprintf("⚠️ Search error: %v", err)
		return
	}

	m.isFilterActive = true
	m.searchQuery = query
	m.events = results
	m.selectedLogIndex = 0
	m.statusPrompt = fmt.Sprintf("🔍 Filter active: '%s' (%d matches found)", query, len(results))
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

func (m *SIEMModel) View() string {
	if m.width == 0 {
		return "Initializing CoPSeC Enterprise Cyber-Defense Cockpit..."
	}

	totalWidth := m.width - 4
	if totalWidth < 80 {
		totalWidth = 80
	}
	leftWidth := totalWidth * 24 / 100
	rightWidth := totalWidth * 32 / 100
	centerWidth := totalWidth - leftWidth - rightWidth - 6

	mainHeight := m.height - 10
	if mainHeight < 16 {
		mainHeight = 16
	}

	streamHeight := mainHeight / 2
	incidentHeight := mainHeight - streamHeight

	// 1. Top Banner
	banner := headerStyle.Render("⚡ CoPSeC ENTERPRISE CYBER-DEFENSE COCKPIT") + " " +
		matrixTitleStyle.Render("v2.0 [DUAL-WINDOW SOC]") + "\n"

	// 2. Left Panel: Fleet Matrix & Telemetry
	leftContent := m.renderFleetPanel(leftWidth - 2)
	leftStyle := panelStyle
	if m.activeTab == 0 {
		leftStyle = activePanelStyle
	}
	leftPanel := leftStyle.Width(leftWidth).Height(mainHeight).Render(leftContent)

	// 3. Center Panels (Dual-Window): Top Ingestion Stream + Bottom Incident Alerts
	centerTopContent := m.renderThreatStream(centerWidth-2, streamHeight-2)
	topStyle := panelStyle
	if m.activeTab == 1 {
		topStyle = activePanelStyle
	}
	centerTopPanel := topStyle.Width(centerWidth).Height(streamHeight).Render(centerTopContent)

	centerBottomContent := m.renderIncidentStream(centerWidth-2, incidentHeight-2)
	bottomStyle := panelStyle
	if m.activeTab == 2 {
		bottomStyle = activePanelStyle
	}
	centerBottomPanel := bottomStyle.Width(centerWidth).Height(incidentHeight).Render(centerBottomContent)

	centerColumn := lipgloss.JoinVertical(lipgloss.Left, centerTopPanel, centerBottomPanel)

	// 4. Right Panel: Enterprise MITRE Heatmap & Intel
	rightContent := m.renderMITREPanel(rightWidth-2, mainHeight-2)
	rightStyle := panelStyle
	if m.activeTab == 3 {
		rightStyle = activePanelStyle
	}
	rightPanel := rightStyle.Width(rightWidth).Height(mainHeight).Render(rightContent)

	middleRow := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, centerColumn, rightPanel)

	// 5. Bottom Panel: Metrics & Controls
	bottomContent := m.renderBottomPanel(totalWidth)
	bottomPanel := panelStyle.Width(totalWidth).Height(4).Render(bottomContent)

	baseView := lipgloss.JoinVertical(lipgloss.Left, banner, middleRow, bottomPanel)

	// Overlay Modals
	if m.mode == modalLogDetail {
		return m.renderDetailModalOverlay(baseView)
	} else if m.mode == modalSearch {
		return m.renderSearchModalOverlay(baseView)
	} else if m.mode != modalNone {
		return m.renderModalOverlay(baseView)
	}

	return baseView
}

func renderMiniBar(pct float64, width int) string {
	if width <= 0 {
		width = 8
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

func (m *SIEMModel) renderFleetPanel(width int) string {
	var b strings.Builder
	b.WriteString(matrixTitleStyle.Render("🌐 FLEET MATRIX & TELEMETRY") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	if len(m.nodes) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("No edge nodes connected.\n(Listening on gRPC 0.0.0.0:50051...)"))
		return b.String()
	}

	for _, n := range m.nodes {
		isOnline := time.Since(n.LastSeen) <= 20*time.Second
		statusBadge := lipgloss.NewStyle().Foreground(colorNeonGreen).Render("🟢 ACTIVE")
		if !isOnline {
			statusBadge = alertStyle.Render("🔴 OFFLINE")
		}

		nodeName := n.NodeID
		cpuBar := renderMiniBar(n.CPUUsage, 8)
		ramBar := renderMiniBar(n.MemoryUsage/256.0*100.0, 8)

		b.WriteString(fmt.Sprintf("%s %s\n", statusBadge, lipgloss.NewStyle().Bold(true).Foreground(colorCyberCyan).Render(nodeName)))
		b.WriteString(fmt.Sprintf("  CPU: [%s] %0.1f%%\n", lipgloss.NewStyle().Foreground(colorNeonGreen).Render(cpuBar), n.CPUUsage))
		b.WriteString(fmt.Sprintf("  RAM: [%s] %0.1f MB\n", lipgloss.NewStyle().Foreground(colorCyberCyan).Render(ramBar), n.MemoryUsage))
		b.WriteString(fmt.Sprintf("  🛡️ Bans: %d  | ⏱️ Up: %ds\n", n.ActiveBansCount, n.UptimeSeconds))
		b.WriteString("\n")
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
	filterTag := ""
	if m.isFilterActive {
		filterTag = fmt.Sprintf(" 🔍 [FILTER: %s]", m.searchQuery)
	}

	b.WriteString(fmt.Sprintf("%s %s%s%s\n",
		headerStyle.Render("⚡ LIVE INGESTION STREAM"),
		lipgloss.NewStyle().Foreground(colorNeonGreen).Render(fmt.Sprintf("(%d EPS)", eps)),
		alertStyle.Render(pauseTag),
		lipgloss.NewStyle().Foreground(colorWarningGold).Render(filterTag)))
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	if len(m.events) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("Listening for edge node stream events on gRPC...\n"))
		return b.String()
	}

	limit := maxLines / 2
	if limit <= 0 {
		limit = 4
	}

	for i, ev := range m.events {
		if i >= limit {
			break
		}

		timeStr := time.UnixMilli(ev.TimestampMs).Format("15:04:05")
		srcIcon := "🌐 HTTP"
		if ev.Source == "ssh" {
			srcIcon = "🔑 AUTH"
		} else if ev.Source == "syslog" {
			srcIcon = "⚡ SYS"
		}

		scoreBadge := lipgloss.NewStyle().Foreground(colorNeonGreen).Render(fmt.Sprintf("[%d]", ev.ThreatScore))
		if ev.ThreatScore >= 80 {
			scoreBadge = alertStyle.Render(fmt.Sprintf("[CRIT %d]", ev.ThreatScore))
		} else if ev.ThreatScore >= 50 {
			scoreBadge = lipgloss.NewStyle().Bold(true).Foreground(colorWarningGold).Render(fmt.Sprintf("[WARN %d]", ev.ThreatScore))
		}

		prefix := "  "
		if m.activeTab == 1 && i == m.selectedLogIndex {
			prefix = "▶ "
		}

		line1 := fmt.Sprintf("%s%s %s %s 🎯 %s 🏷 %s",
			prefix,
			lipgloss.NewStyle().Foreground(colorTextMuted).Render(timeStr),
			scoreBadge,
			lipgloss.NewStyle().Foreground(colorCyberCyan).Render(srcIcon),
			lipgloss.NewStyle().Bold(true).Foreground(colorTextLight).Render(ev.ClientIP),
			lipgloss.NewStyle().Foreground(colorWarningGold).Render(ev.MitreTechniqueID),
		)
		line2 := fmt.Sprintf("    %s", lipgloss.NewStyle().Foreground(colorTextMuted).Render(truncateString(ev.RawLine, width-6)))

		if m.activeTab == 1 && i == m.selectedLogIndex {
			b.WriteString(lipgloss.NewStyle().Background(colorSelectedBg).Render(line1) + "\n")
			b.WriteString(lipgloss.NewStyle().Background(colorSelectedBg).Render(line2) + "\n")
		} else {
			b.WriteString(line1 + "\n" + line2 + "\n")
		}
	}
	return b.String()
}

func (m *SIEMModel) renderIncidentStream(width, maxLines int) string {
	var b strings.Builder
	b.WriteString(alertStyle.Render("🔥 CRITICAL & WARN INCIDENTS (THREAT >= 50)") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	if len(m.incidents) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("No critical incidents logged. Threat perimeter secure.\n"))
		return b.String()
	}

	limit := maxLines / 2
	if limit <= 0 {
		limit = 4
	}

	for i, ev := range m.incidents {
		if i >= limit {
			break
		}

		timeStr := time.UnixMilli(ev.TimestampMs).Format("15:04:05")
		scoreBadge := alertStyle.Render(fmt.Sprintf("[CRIT %d]", ev.ThreatScore))
		if ev.ThreatScore < 70 {
			scoreBadge = lipgloss.NewStyle().Bold(true).Foreground(colorWarningGold).Render(fmt.Sprintf("[WARN %d]", ev.ThreatScore))
		}

		prefix := "  "
		if m.activeTab == 2 && i == m.selectedIncIndex {
			prefix = "▶ "
		}

		line1 := fmt.Sprintf("%s%s %s 🎯 %s 🏷 %s (%s)",
			prefix,
			lipgloss.NewStyle().Foreground(colorTextMuted).Render(timeStr),
			scoreBadge,
			lipgloss.NewStyle().Bold(true).Foreground(colorAlertPink).Render(ev.ClientIP),
			lipgloss.NewStyle().Foreground(colorWarningGold).Render(ev.MitreTechniqueID),
			lipgloss.NewStyle().Foreground(colorCyberCyan).Render(ev.RuleID),
		)
		line2 := fmt.Sprintf("    %s", lipgloss.NewStyle().Foreground(colorTextLight).Render(truncateString(ev.RawLine, width-6)))

		if m.activeTab == 2 && i == m.selectedIncIndex {
			b.WriteString(lipgloss.NewStyle().Background(colorSelectedBg).Render(line1) + "\n")
			b.WriteString(lipgloss.NewStyle().Background(colorSelectedBg).Render(line2) + "\n")
		} else {
			b.WriteString(line1 + "\n" + line2 + "\n")
		}
	}
	return b.String()
}

func (m *SIEMModel) renderMITREPanel(width, maxLines int) string {
	var b strings.Builder
	b.WriteString(matrixTitleStyle.Render("🛡 ENTERPRISE MITRE HEATMAP & INTEL") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

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

	limit := maxLines - 8
	if limit <= 0 {
		limit = 8
	}

	for i, st := range list {
		if i >= limit {
			break
		}

		barLen := 0
		if st.Count > 0 {
			barLen = min(st.Count/2+1, 8)
		}
		filled := strings.Repeat("█", barLen)
		empty := strings.Repeat("░", 8-barLen)

		techName := st.Name
		if len(techName) > 16 {
			techName = techName[:16]
		}

		color := colorCyberCyan
		if st.Count >= 20 {
			color = colorAlertPink
		} else if st.Count >= 5 {
			color = colorWarningGold
		}

		b.WriteString(fmt.Sprintf("%-6s %-16s %s%s %2d\n",
			lipgloss.NewStyle().Bold(true).Foreground(color).Render(st.ID),
			lipgloss.NewStyle().Foreground(colorTextLight).Render(techName),
			lipgloss.NewStyle().Foreground(colorAlertPink).Render(filled),
			lipgloss.NewStyle().Foreground(colorPanelBorder).Render(empty),
			st.Count))
	}

	// Intel Box: Top Attacker IPs
	b.WriteString("\n" + lipgloss.NewStyle().Bold(true).Foreground(colorWarningGold).Render("🎯 TOP ATTACKER INTEL") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	var attackers []attackerStat
	for ip, count := range m.attackerMap {
		attackers = append(attackers, attackerStat{IP: ip, Count: count})
	}
	sort.Slice(attackers, func(i, j int) bool {
		return attackers[i].Count > attackers[j].Count
	})

	if len(attackers) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("No threat actors logged yet\n"))
	} else {
		for i, at := range attackers {
			if i >= 3 {
				break
			}
			b.WriteString(fmt.Sprintf("⚡ %-18s [%s hits]\n",
				lipgloss.NewStyle().Bold(true).Foreground(colorAlertPink).Render(at.IP),
				lipgloss.NewStyle().Foreground(colorNeonGreen).Render(strconv.Itoa(at.Count))))
		}
	}

	return b.String()
}

func (m *SIEMModel) renderBottomPanel(width int) string {
	var sparkline strings.Builder
	maxRate := 0
	for _, val := range m.rateHistory {
		if val > maxRate {
			maxRate = val
		}
		if val == 0 {
			sparkline.WriteString(" ")
		} else if val < 10 {
			sparkline.WriteString("▃")
		} else if val < 50 {
			sparkline.WriteString("▅")
		} else {
			sparkline.WriteString("█")
		}
	}

	eps := m.server.GetEPS()
	total := m.server.GetTotalEvents()

	threatIndex := lipgloss.NewStyle().Bold(true).Foreground(colorNeonGreen).Render("🟢 LOW")
	if maxRate > 40 || eps > 20 {
		threatIndex = alertStyle.Render("🔴 CRITICAL")
	} else if maxRate > 10 || eps > 5 {
		threatIndex = lipgloss.NewStyle().Bold(true).Foreground(colorWarningGold).Render("🟡 ELEVATED")
	}

	shortcuts := lipgloss.NewStyle().Foreground(colorCyberCyan).Render("[/] Search  |  [B] Ban  |  [U] Unban  |  [Space] Pause  |  [Tab] Focus  |  [Enter] Inspect  |  [Q] Quit")
	rateDisplay := lipgloss.NewStyle().Bold(true).Foreground(colorNeonGreen).Render(fmt.Sprintf("EPS: [%d]  Total: [%s]  Threat: [%s]", eps, strconv.FormatUint(total, 10), threatIndex))
	graph := lipgloss.NewStyle().Foreground(colorCyberCyan).Render(fmt.Sprintf("[%s]", sparkline.String()))

	status := m.statusPrompt
	if status != "" {
		status = alertStyle.Render(" " + status)
	}

	return fmt.Sprintf("%s   %s %s%s\n%s", shortcuts, rateDisplay, graph, status,
		lipgloss.NewStyle().Foreground(colorTextMuted).Render("CoPSeC Enterprise SOC Cockpit • Dual-Window Threat Hunting Core"))
}

func (m *SIEMModel) renderSearchModalOverlay(baseView string) string {
	title := "🔍 THREAT HUNTING SEARCH MATRIX"
	prompt := "Syntax: ip:1.2.3.4  |  mitre:T1190  |  score:>70  |  src:nginx  |  q:keyword"

	content := fmt.Sprintf("%s\n\n%s\n\n> %s█\n\n%s",
		headerStyle.Render(title),
		lipgloss.NewStyle().Foreground(colorTextMuted).Render(prompt),
		lipgloss.NewStyle().Bold(true).Foreground(colorNeonGreen).Render(m.inputSearch),
		lipgloss.NewStyle().Foreground(colorTextMuted).Render("[Enter] Execute Query   [Esc] Cancel / Clear Filter"),
	)

	modalBox := searchBoxStyle.Render(content)
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
		alertStyle.Render(title),
		lipgloss.NewStyle().Foreground(colorTextLight).Render(prompt),
		lipgloss.NewStyle().Bold(true).Foreground(colorCyberCyan).Render(m.inputIP),
		lipgloss.NewStyle().Foreground(colorTextMuted).Render("[Enter] Confirm Action   [Esc] Cancel"),
	)

	modalBox := modalBoxStyle.Render(content)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modalBox,
		lipgloss.WithWhitespaceChars(" "),
		lipgloss.WithWhitespaceForeground(colorDarkBg),
	)
}

func (m *SIEMModel) renderDetailModalOverlay(baseView string) string {
	var ev *StoredEvent
	if m.activeTab == 2 && len(m.incidents) > 0 && m.selectedIncIndex < len(m.incidents) {
		ev = m.incidents[m.selectedIncIndex]
	} else if len(m.events) > 0 && m.selectedLogIndex < len(m.events) {
		ev = m.events[m.selectedLogIndex]
	}

	if ev == nil {
		m.mode = modalNone
		return baseView
	}

	analyzer := m.server.GetAnalyzer()
	techName, tactic := "", ""
	if analyzer != nil {
		techName, tactic = analyzer.GetTechniqueMeta(ev.MitreTechniqueID)
	}

	aiSection := ""
	if ev.AIAnalysis != "" {
		aiSection = fmt.Sprintf("\n🧠  AI Threat Intelligence:\n%s\n", lipgloss.NewStyle().Foreground(colorNeonGreen).Render(ev.AIAnalysis))
	}

	content := fmt.Sprintf("🔍 %s\n\n"+
		"🖥  Node ID:         %s\n"+
		"🌐  Source:          %s\n"+
		"🎯  Attacker IP:     %s\n"+
		"🏷  MITRE Technique: %s (%s)\n"+
		"🛡  MITRE Tactic:    %s\n"+
		"⚡  Threat Score:    %d/100\n"+
		"⏱  Timestamp:       %s\n\n"+
		"📜  Raw Log Payload:\n%s\n"+
		"%s\n"+
		"%s",
		lipgloss.NewStyle().Bold(true).Foreground(colorCyberCyan).Render("SECURITY INCIDENT FORENSIC INSPECTION"),
		lipgloss.NewStyle().Foreground(colorTextLight).Render(ev.NodeID),
		lipgloss.NewStyle().Foreground(colorNeonGreen).Render(ev.Source),
		lipgloss.NewStyle().Bold(true).Foreground(colorAlertPink).Render(ev.ClientIP),
		lipgloss.NewStyle().Bold(true).Foreground(colorWarningGold).Render(ev.MitreTechniqueID),
		techName,
		lipgloss.NewStyle().Foreground(colorCyberCyan).Render(tactic),
		ev.ThreatScore,
		time.UnixMilli(ev.TimestampMs).Format("2006-01-02 15:04:05.000"),
		lipgloss.NewStyle().Foreground(colorTextLight).Render(ev.RawLine),
		aiSection,
		lipgloss.NewStyle().Foreground(colorTextMuted).Render("[Esc / Enter] Close Inspection Modal"),
	)

	detailBox := detailBoxStyle.Render(content)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, detailBox,
		lipgloss.WithWhitespaceChars(" "),
		lipgloss.WithWhitespaceForeground(colorDarkBg),
	)
}
