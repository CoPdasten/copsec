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

	// Base Panel Styles
	basePanelStyle = lipgloss.NewStyle().
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

	inspectionCardStyle = lipgloss.NewStyle().
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
	GeoTag    string
	Count     int
	TopTarget string
}

// SIEMModel holds the state for the 6-panel SOC cockpit with Threat Hunting & GeoIP radar.
type SIEMModel struct {
	server       *CentralServer
	storage      *StorageEngine
	width        int
	height       int
	events       []*StoredEvent
	incidents    []*StoredEvent
	nodes        []NodeSession
	activeBans   []ActiveBanRecord
	soarActions  []SOARActionRecord
	mitreMap     map[string]int
	attackerMap  map[string]*attackerIntel
	activeTab    int
	rateHistory  []int
	peakEPS      int
	statusPrompt string
	isPaused     bool

	// Threat Hunting Search
	searchQuery    string
	isFilterActive bool
	inputSearch    string

	// Navigation & Cursor Binding
	selectedLogIndex int
	selectedIncIndex int
	inspectEvent     *StoredEvent

	// Async event queue buffer
	mu          sync.Mutex
	eventBuffer []*StoredEvent

	// Modal State
	mode    modalMode
	inputIP string
}

// NewSIEMModel creates a new 6-panel TUI dashboard model.
func NewSIEMModel(server *CentralServer, storage *StorageEngine) *SIEMModel {
	m := &SIEMModel{
		server:      server,
		storage:     storage,
		mitreMap:    make(map[string]int),
		attackerMap: make(map[string]*attackerIntel),
		rateHistory: make([]int, 20),
	}

	// Initialize default core techniques
	defaultCore := []string{"T1190", "T1059.004", "T1203", "T1078", "T1053.003", "T1548.001", "T1027", "T1070.003", "T1562.001", "T1110.001", "T1003.008", "T1552.001", "T1595.002", "T1082", "T1087.001", "T1046", "T1071.001", "T1041", "T1567"}
	for _, t := range defaultCore {
		m.mitreMap[t] = 0
	}

	// Load historical stats, incidents and bans from DB
	if stats, err := storage.GetMITREStats(); err == nil {
		for _, s := range stats {
			m.mitreMap[s.TechniqueID] = s.Count
		}
	}
	if incs, err := storage.GetCriticalEvents(30); err == nil {
		m.incidents = incs
	}
	if bans, err := storage.GetActiveBans(); err == nil {
		m.activeBans = bans
	}
	if actions, err := storage.GetRecentSOARActions(5); err == nil {
		m.soarActions = actions
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

// lookupGeoTag assigns an ASN / Geo threat actor tag to IP addresses.
func lookupGeoTag(ip string) string {
	if strings.HasPrefix(ip, "185.220.") || strings.HasPrefix(ip, "185.222.") || strings.HasPrefix(ip, "104.244.") {
		return "DE - Tor Exit Node"
	} else if strings.HasPrefix(ip, "45.154.") || strings.HasPrefix(ip, "194.26.") || strings.HasPrefix(ip, "193.106.") {
		return "RU - Scanner/Nuclei"
	} else if strings.HasPrefix(ip, "176.") || strings.HasPrefix(ip, "88.") || strings.HasPrefix(ip, "212.") || strings.HasPrefix(ip, "78.") {
		return "TR - Turkcell/ISP"
	} else if strings.HasPrefix(ip, "34.") || strings.HasPrefix(ip, "35.") || strings.HasPrefix(ip, "54.") || strings.HasPrefix(ip, "52.") {
		return "US - Cloud Provider"
	} else if strings.HasPrefix(ip, "198.51.100.") || strings.HasPrefix(ip, "203.0.113.") {
		return "DOC - Threat Test IP"
	}
	return "EXT - Public WAN"
}

func extractTarget(rawLine string) string {
	parts := strings.Fields(rawLine)
	for _, p := range parts {
		if strings.HasPrefix(p, "/") {
			if len(p) > 22 {
				return p[:22]
			}
			return p
		}
	}
	if strings.Contains(rawLine, "SSH") || strings.Contains(rawLine, "password") {
		return "SSH Service (22)"
	}
	return "Web / API Endpoint"
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
			if m.activeTab == 2 { // Critical Incidents
				if m.selectedIncIndex > 0 {
					m.selectedIncIndex--
				}
			} else { // Live Stream
				if m.selectedLogIndex > 0 {
					m.selectedLogIndex--
				}
			}
		case "down", "j":
			if m.activeTab == 2 { // Critical Incidents
				if m.selectedIncIndex < len(m.incidents)-1 && m.selectedIncIndex < 15 {
					m.selectedIncIndex++
				}
			} else { // Live Stream
				if m.selectedLogIndex < len(m.events)-1 && m.selectedLogIndex < 15 {
					m.selectedLogIndex++
				}
			}
		case "enter":
			if m.activeTab == 2 && len(m.incidents) > 0 && m.selectedIncIndex < len(m.incidents) {
				m.inspectEvent = m.incidents[m.selectedIncIndex]
				m.mode = modalLogDetail
			} else if len(m.events) > 0 && m.selectedLogIndex < len(m.events) {
				m.inspectEvent = m.events[m.selectedLogIndex]
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
					if existing, ok := m.attackerMap[ev.ClientIP]; ok {
						existing.Count++
						if existing.TopTarget == "" {
							existing.TopTarget = extractTarget(ev.RawLine)
						}
					} else {
						m.attackerMap[ev.ClientIP] = &attackerIntel{
							IP:        ev.ClientIP,
							GeoTag:    lookupGeoTag(ev.ClientIP),
							Count:     1,
							TopTarget: extractTarget(ev.RawLine),
						}
					}
				}
			}
			m.eventBuffer = nil
			if len(m.events) > 80 {
				m.events = m.events[:80]
			}
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

	// 1. Strict Grid Math Calculation
	leftWidth := int(float64(m.width) * 0.23)
	if leftWidth < 24 {
		leftWidth = 24
	} else if leftWidth > 32 {
		leftWidth = 32
	}

	rightWidth := int(float64(m.width) * 0.29)
	if rightWidth < 30 {
		rightWidth = 30
	}

	centerWidth := m.width - leftWidth - rightWidth - 6
	if centerWidth < 30 {
		centerWidth = 30
	}

	mainHeight := m.height - 4
	if mainHeight < 16 {
		mainHeight = 16
	}

	// Vertical splits
	topHeight := int(float64(mainHeight) * 0.52)
	if topHeight < 6 {
		topHeight = 6
	}
	bottomHeight := mainHeight - topHeight - 2
	if bottomHeight < 6 {
		bottomHeight = 6
	}

	// 2. Top Banner
	banner := headerStyle.Render("⚡ CoPSeC ENTERPRISE CYBER-DEFENSE COCKPIT") + " " +
		matrixTitleStyle.Render("v2.0 [6-PANEL SOC MATRIX]")

	// 3. Left Column: Top Fleet Matrix + Bottom SOAR Jail & Mitigations
	leftTopContent := m.renderFleetPanel(leftWidth-2, topHeight-2)
	leftTopPanel := basePanelStyle.Width(leftWidth).Height(topHeight).MaxHeight(topHeight).Render(leftTopContent)

	leftBottomContent := m.renderJailPanel(leftWidth-2, bottomHeight-2)
	leftBottomPanel := basePanelStyle.Width(leftWidth).Height(bottomHeight).MaxHeight(bottomHeight).Render(leftBottomContent)

	leftColumn := lipgloss.JoinVertical(lipgloss.Left, leftTopPanel, leftBottomPanel)

	// 4. Center Column: Top Raw Stream + Bottom Critical Incidents
	centerTopContent := m.renderThreatStream(centerWidth-2, topHeight-2)
	topStyle := basePanelStyle
	if m.activeTab == 1 {
		topStyle = activePanelStyle
	}
	centerTopPanel := topStyle.Width(centerWidth).Height(topHeight).MaxHeight(topHeight).Render(centerTopContent)

	centerBottomContent := m.renderIncidentStream(centerWidth-2, bottomHeight-2)
	bottomStyle := basePanelStyle
	if m.activeTab == 2 {
		bottomStyle = activePanelStyle
	}
	centerBottomPanel := bottomStyle.Width(centerWidth).Height(bottomHeight).MaxHeight(bottomHeight).Render(centerBottomContent)

	centerColumn := lipgloss.JoinVertical(lipgloss.Left, centerTopPanel, centerBottomPanel)

	// 5. Right Column: Top Enterprise MITRE Heatmap + Bottom Geo Threat Radar & Actors
	rightTopContent := m.renderMITREPanel(rightWidth-2, topHeight-2)
	rightTopPanel := basePanelStyle.Width(rightWidth).Height(topHeight).MaxHeight(topHeight).Render(rightTopContent)

	rightBottomContent := m.renderThreatIntelPanel(rightWidth-2, bottomHeight-2)
	rightBottomPanel := basePanelStyle.Width(rightWidth).Height(bottomHeight).MaxHeight(bottomHeight).Render(rightBottomContent)

	rightColumn := lipgloss.JoinVertical(lipgloss.Left, rightTopPanel, rightBottomPanel)

	// Horizontal Join for the 3 main columns
	middleRow := lipgloss.JoinHorizontal(lipgloss.Top, leftColumn, centerColumn, rightColumn)

	// 6. Bottom Bar: Metrics & Controls
	bottomContent := m.renderBottomPanel(m.width - 2)
	bottomPanel := lipgloss.NewStyle().Width(m.width).Render(bottomContent)

	baseView := lipgloss.JoinVertical(lipgloss.Left, banner, middleRow, bottomPanel)

	// Overlay Modals
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
	b.WriteString(matrixTitleStyle.Render("🌐 FLEET MATRIX") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	if len(m.nodes) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("No edge nodes connected.\n(gRPC 0.0.0.0:50051)"))
		return b.String()
	}

	for _, n := range m.nodes {
		isOnline := time.Since(n.LastSeen) <= 20*time.Second
		statusBadge := lipgloss.NewStyle().Foreground(colorNeonGreen).Render("🟢")
		if !isOnline {
			statusBadge = alertStyle.Render("🔴")
		}

		nodeName := truncateString(n.NodeID, width-4)
		cpuBar := renderMiniBar(n.CPUUsage, 6)
		ramBar := renderMiniBar(n.MemoryUsage/256.0*100.0, 6)

		b.WriteString(fmt.Sprintf("%s %s\n", statusBadge, lipgloss.NewStyle().Bold(true).Foreground(colorCyberCyan).Render(nodeName)))
		b.WriteString(fmt.Sprintf(" CPU:[%s] %0.0f%%\n", lipgloss.NewStyle().Foreground(colorNeonGreen).Render(cpuBar), n.CPUUsage))
		b.WriteString(fmt.Sprintf(" RAM:[%s] %0.0fMB\n", lipgloss.NewStyle().Foreground(colorCyberCyan).Render(ramBar), n.MemoryUsage))
		b.WriteString(fmt.Sprintf(" 🛡️ %d | ⏱ %ds\n", n.ActiveBansCount, n.UptimeSeconds))
	}
	return b.String()
}

func (m *SIEMModel) renderJailPanel(width, maxLines int) string {
	var b strings.Builder
	b.WriteString(alertStyle.Render("🛡 SOAR JAIL & MITIGATIONS") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	if len(m.activeBans) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("No active IP isolations.\nAll perimeter guards idle.\n"))
	} else {
		limit := maxLines - 3
		if limit <= 0 {
			limit = 2
		}
		for i, ban := range m.activeBans {
			if i >= limit {
				break
			}
			elapsedSec := (time.Now().UnixMilli() - ban.BanTimeMs) / 1000
			remSec := ban.DurationSeconds - elapsedSec
			remStr := fmt.Sprintf("%dm", remSec/60)
			if remSec <= 0 {
				remStr = "exp"
			}

			reason := ban.Reason
			if len(reason) > 10 {
				reason = reason[:10]
			}

			line := fmt.Sprintf("🚫 %-14s %s %s", truncateString(ban.IP, 14), lipgloss.NewStyle().Foreground(colorWarningGold).Render(reason), remStr)
			b.WriteString(truncateString(line, width) + "\n")
		}
	}

	// Recent SOAR Actions
	if len(m.soarActions) > 0 {
		act := m.soarActions[0]
		b.WriteString(lipgloss.NewStyle().Foreground(colorNeonGreen).Render(fmt.Sprintf("[ACK] %s %s (%dn)", act.ActionType, truncateString(act.TargetIP, 11), act.NodesCount)))
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
		filterTag = fmt.Sprintf(" [FILTER: %s]", truncateString(m.searchQuery, 12))
	}

	header := fmt.Sprintf("%s %s%s%s",
		headerStyle.Render("⚡ LIVE INGESTION STREAM"),
		lipgloss.NewStyle().Foreground(colorNeonGreen).Render(fmt.Sprintf("(%d EPS)", eps)),
		alertStyle.Render(pauseTag),
		lipgloss.NewStyle().Foreground(colorWarningGold).Render(filterTag))
	b.WriteString(truncateString(header, width) + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	if len(m.events) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("Listening for edge node stream events...\n"))
		return b.String()
	}

	limit := maxLines / 2
	if limit <= 0 {
		limit = 3
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
			b.WriteString(lipgloss.NewStyle().Background(colorSelectedBg).Render(truncateString(line1, width)) + "\n")
			b.WriteString(lipgloss.NewStyle().Background(colorSelectedBg).Render(truncateString(line2, width)) + "\n")
		} else {
			b.WriteString(truncateString(line1, width) + "\n" + truncateString(line2, width) + "\n")
		}
	}
	return b.String()
}

func (m *SIEMModel) renderIncidentStream(width, maxLines int) string {
	var b strings.Builder
	b.WriteString(alertStyle.Render("🔥 CRITICAL INCIDENTS (THREAT >= 50)") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	if len(m.incidents) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("No critical incidents logged. Threat perimeter secure.\n"))
		return b.String()
	}

	limit := maxLines / 2
	if limit <= 0 {
		limit = 3
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
			lipgloss.NewStyle().Foreground(colorCyberCyan).Render(truncateString(ev.RuleID, 16)),
		)
		line2 := fmt.Sprintf("    %s", lipgloss.NewStyle().Foreground(colorTextLight).Render(truncateString(ev.RawLine, width-6)))

		if m.activeTab == 2 && i == m.selectedIncIndex {
			b.WriteString(lipgloss.NewStyle().Background(colorSelectedBg).Render(truncateString(line1, width)) + "\n")
			b.WriteString(lipgloss.NewStyle().Background(colorSelectedBg).Render(truncateString(line2, width)) + "\n")
		} else {
			b.WriteString(truncateString(line1, width) + "\n" + truncateString(line2, width) + "\n")
		}
	}
	return b.String()
}

func (m *SIEMModel) renderMITREPanel(width, maxLines int) string {
	var b strings.Builder
	b.WriteString(matrixTitleStyle.Render("🛡 ENTERPRISE MITRE INTEL") + "\n")
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

	limit := maxLines - 2
	if limit <= 0 {
		limit = 4
	}

	for i, st := range list {
		if i >= limit {
			break
		}

		barLen := 0
		if st.Count > 0 {
			barLen = min(st.Count/2+1, 6)
		}
		filled := strings.Repeat("█", barLen)
		empty := strings.Repeat("░", 6-barLen)

		techName := st.Name
		if len(techName) > 12 {
			techName = techName[:12]
		}

		color := colorCyberCyan
		if st.Count >= 20 {
			color = colorAlertPink
		} else if st.Count >= 5 {
			color = colorWarningGold
		}

		row := fmt.Sprintf("%-6s %-12s %s%s %2d",
			lipgloss.NewStyle().Bold(true).Foreground(color).Render(st.ID),
			lipgloss.NewStyle().Foreground(colorTextLight).Render(techName),
			lipgloss.NewStyle().Foreground(colorAlertPink).Render(filled),
			lipgloss.NewStyle().Foreground(colorPanelBorder).Render(empty),
			st.Count)
		b.WriteString(truncateString(row, width) + "\n")
	}

	return b.String()
}

func (m *SIEMModel) renderThreatIntelPanel(width, maxLines int) string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(colorWarningGold).Render("🌐 GEOGRAPHIC THREAT RADAR & ACTORS") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	var attackers []*attackerIntel
	for _, at := range m.attackerMap {
		attackers = append(attackers, at)
	}
	sort.Slice(attackers, func(i, j int) bool {
		return attackers[i].Count > attackers[j].Count
	})

	if len(attackers) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("No threat actors logged yet\n"))
	} else {
		limit := maxLines - 2
		if limit <= 0 {
			limit = 3
		}
		for i, at := range attackers {
			if i >= limit {
				break
			}
			row1 := fmt.Sprintf("🔴 %-15s [%s]",
				lipgloss.NewStyle().Bold(true).Foreground(colorAlertPink).Render(at.IP),
				lipgloss.NewStyle().Foreground(colorNeonGreen).Render(fmt.Sprintf("%d reqs", at.Count)))
			row2 := fmt.Sprintf("   └ %s 🎯 %s",
				lipgloss.NewStyle().Foreground(colorCyberCyan).Render(at.GeoTag),
				lipgloss.NewStyle().Foreground(colorTextMuted).Render(at.TopTarget))
			b.WriteString(truncateString(row1, width) + "\n")
			b.WriteString(truncateString(row2, width) + "\n")
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
	rateDisplay := lipgloss.NewStyle().Bold(true).Foreground(colorNeonGreen).Render(fmt.Sprintf("EPS:[%d] Peak:[%d] Total:[%s] Threat:[%s]", eps, m.peakEPS, strconv.FormatUint(total, 10), threatIndex))
	velocity := fmt.Sprintf("THREAT VELOCITY:[%s]", lipgloss.NewStyle().Foreground(colorCyberCyan).Render(sparkline.String()))

	status := m.statusPrompt
	if status != "" {
		status = alertStyle.Render(" " + status)
	}

	line1 := fmt.Sprintf("%s   %s  %s%s", shortcuts, rateDisplay, velocity, status)
	return truncateString(line1, width)
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
		lipgloss.NewStyle().Bold(true).Foreground(colorCyberCyan).Render("FORENSIC INCIDENT INSPECTION"),
		lipgloss.NewStyle().Foreground(colorTextLight).Render(timeStr),
		lipgloss.NewStyle().Foreground(colorNeonGreen).Render(ev.NodeID),
		lipgloss.NewStyle().Foreground(colorCyberCyan).Render(sourceLabel),
		alertStyle.Render(scoreLabel),
		lipgloss.NewStyle().Foreground(colorWarningGold).Render(tactic),
		lipgloss.NewStyle().Bold(true).Foreground(colorCyberCyan).Render(ev.MitreTechniqueID),
		techName,
		lipgloss.NewStyle().Bold(true).Foreground(colorAlertPink).Render(ev.ClientIP),
		lipgloss.NewStyle().Bold(true).Foreground(colorWarningGold).Render("DECODED PAYLOAD"),
		lipgloss.NewStyle().Foreground(colorTextLight).Render(decodedPayload),
		lipgloss.NewStyle().Bold(true).Foreground(colorNeonGreen).Render("AI INTEL & INTENT"),
		lipgloss.NewStyle().Foreground(colorTextMuted).Render(aiIntelText),
		lipgloss.NewStyle().Foreground(colorTextMuted).Render("[Esc / Enter] Close Inspection Modal"),
	)

	card := inspectionCardStyle.Render(content)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, card,
		lipgloss.WithWhitespaceChars(" "),
		lipgloss.WithWhitespaceForeground(colorDarkBg),
	)
}
