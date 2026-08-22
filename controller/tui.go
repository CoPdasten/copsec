package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Cyberpunk / Matrix Color Palette
var (
	colorNeonGreen  = lipgloss.Color("#00FF66")
	colorCyberCyan  = lipgloss.Color("#00F0FF")
	colorAlertPink  = lipgloss.Color("#FF0055")
	colorWarningGold = lipgloss.Color("#FFB800")
	colorDarkBg     = lipgloss.Color("#0A0E14")
	colorPanelBorder = lipgloss.Color("#1E293B")
	colorTextMuted  = lipgloss.Color("#64748B")
	colorTextLight  = lipgloss.Color("#E2E8F0")

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
			Width(50)
)

type tickMsg time.Time

type modalMode int

const (
	modalNone modalMode = iota
	modalBanIP
	modalUnbanIP
)

// SIEMModel holds the state for the high-performance async Bubbletea dashboard.
type SIEMModel struct {
	server       *CentralServer
	storage      *StorageEngine
	width        int
	height       int
	events       []*StoredEvent
	nodes        []NodeSession
	mitreMap     map[string]int
	activeTab    int
	rateHistory  []int
	statusPrompt string

	// Async event queue buffer to prevent TUI blocking
	mu          sync.Mutex
	eventBuffer []*StoredEvent

	// Interactive Modal State
	mode       modalMode
	inputIP    string
	inputHours string
}

// NewSIEMModel creates a new TUI dashboard model with async ingestion.
func NewSIEMModel(server *CentralServer, storage *StorageEngine) *SIEMModel {
	m := &SIEMModel{
		server:      server,
		storage:     storage,
		mitreMap:    make(map[string]int),
		rateHistory: make([]int, 25),
	}

	// Initialize with historical MITRE stats from DB
	if stats, err := storage.GetMITREStats(); err == nil {
		for _, s := range stats {
			m.mitreMap[s.TechniqueID] = s.Count
		}
	}

	// Background worker reading events into memory buffer
	go func() {
		sub := server.SubscribeEvents()
		for ev := range sub {
			m.mu.Lock()
			m.eventBuffer = append(m.eventBuffer, ev)
			if len(m.eventBuffer) > 2000 {
				m.eventBuffer = m.eventBuffer[1000:] // Drop older in buffer if extreme overflow
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
				m.mode = modalNone
				m.inputIP = ""
				m.inputHours = ""
			case "enter":
				m.submitModal()
			case "backspace":
				if len(m.inputIP) > 0 {
					m.inputIP = m.inputIP[:len(m.inputIP)-1]
				}
			default:
				if len(msg.String()) == 1 {
					m.inputIP += msg.String()
				}
			}
			return m, nil
		}

		// Normal shortcuts
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.activeTab = (m.activeTab + 1) % 3
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
				m.events = append([]*StoredEvent{ev}, m.events...)
				if ev.MitreTechniqueID != "" {
					m.mitreMap[ev.MitreTechniqueID]++
				}
			}
			m.eventBuffer = nil
			if len(m.events) > 60 {
				m.events = m.events[:60]
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
		return "Initializing CoPSeC Matrix Dashboard..."
	}

	totalWidth := m.width - 4
	if totalWidth < 80 {
		totalWidth = 80
	}
	leftWidth := totalWidth * 24 / 100
	rightWidth := totalWidth * 26 / 100
	centerWidth := totalWidth - leftWidth - rightWidth - 6

	mainHeight := m.height - 10
	if mainHeight < 12 {
		mainHeight = 12
	}

	// 1. Top Banner
	banner := headerStyle.Render("⚡ CoPSeC DISTRIBUTED MICRO-SIEM/SOAR") + " " +
		matrixTitleStyle.Render("v2.0 [CYBERPUNK MATRIX]") + "\n"

	// 2. Left Panel: Fleet / Nodes
	leftContent := m.renderFleetPanel(leftWidth - 2)
	leftStyle := panelStyle
	if m.activeTab == 0 {
		leftStyle = activePanelStyle
	}
	leftPanel := leftStyle.Width(leftWidth).Height(mainHeight).Render(leftContent)

	// 3. Center Panel: Live Threat Stream
	centerContent := m.renderThreatStream(centerWidth - 2)
	centerStyle := panelStyle
	if m.activeTab == 1 {
		centerStyle = activePanelStyle
	}
	centerPanel := centerStyle.Width(centerWidth).Height(mainHeight).Render(centerContent)

	// 4. Right Panel: MITRE ATT&CK Matrix
	rightContent := m.renderMITREPanel(rightWidth - 2)
	rightStyle := panelStyle
	if m.activeTab == 2 {
		rightStyle = activePanelStyle
	}
	rightPanel := rightStyle.Width(rightWidth).Height(mainHeight).Render(rightContent)

	middleRow := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, centerPanel, rightPanel)

	// 5. Bottom Panel: Metrics & Controls
	bottomContent := m.renderBottomPanel(totalWidth)
	bottomPanel := panelStyle.Width(totalWidth).Height(4).Render(bottomContent)

	baseView := lipgloss.JoinVertical(lipgloss.Left, banner, middleRow, bottomPanel)

	// Overlay Interactive Modal if open
	if m.mode != modalNone {
		return m.renderModalOverlay(baseView)
	}

	return baseView
}

func (m *SIEMModel) renderFleetPanel(width int) string {
	var b strings.Builder
	b.WriteString(matrixTitleStyle.Render("🌐 FLEET NODES") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	if len(m.nodes) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("No active nodes connected\n(Waiting for gRPC stream...)"))
		return b.String()
	}

	for _, n := range m.nodes {
		// Auto offline if no heartbeat for > 10 seconds
		isOnline := time.Since(n.LastSeen) <= 10*time.Second
		statusBadge := lipgloss.NewStyle().Foreground(colorNeonGreen).Render("🟢 ACTIVE")
		if !isOnline {
			statusBadge = alertStyle.Render("🔴 OFFLINE")
		}

		nodeName := n.NodeID
		if len(nodeName) > 16 {
			nodeName = nodeName[:16]
		}

		b.WriteString(fmt.Sprintf("%s %s\n", statusBadge, lipgloss.NewStyle().Bold(true).Foreground(colorTextLight).Render(nodeName)))
		b.WriteString(fmt.Sprintf("   CPU: %0.1f%% | RAM: %0.1f MB\n", n.CPUUsage, n.MemoryUsage))
		b.WriteString(fmt.Sprintf("   Bans: %d | Up: %ds\n", n.ActiveBansCount, n.UptimeSeconds))
		b.WriteString("\n")
	}
	return b.String()
}

func (m *SIEMModel) renderThreatStream(width int) string {
	var b strings.Builder
	eps := m.server.GetEPS()
	b.WriteString(fmt.Sprintf("%s %s\n",
		headerStyle.Render("⚡ REAL-TIME THREAT INGESTION STREAM"),
		lipgloss.NewStyle().Foreground(colorNeonGreen).Render(fmt.Sprintf("(%d EPS)", eps))))
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	if len(m.events) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("Listening for edge node stream events on gRPC...\n"))
		return b.String()
	}

	for i, ev := range m.events {
		if i >= 12 {
			break
		}

		timeStr := time.UnixMilli(ev.TimestampMs).Format("15:04:05")
		scoreBadge := lipgloss.NewStyle().Foreground(colorNeonGreen).Render(fmt.Sprintf("[%d]", ev.ThreatScore))
		if ev.ThreatScore >= 70 {
			scoreBadge = alertStyle.Render(fmt.Sprintf("[CRIT %d]", ev.ThreatScore))
		} else if ev.ThreatScore >= 40 {
			scoreBadge = lipgloss.NewStyle().Bold(true).Foreground(colorWarningGold).Render(fmt.Sprintf("[WARN %d]", ev.ThreatScore))
		}

		techStr := ev.MitreTechniqueID
		if techStr == "" {
			techStr = "T1595"
		}

		line := fmt.Sprintf("%s %s %s 🎯 %s 🏷 %s\n   %s",
			lipgloss.NewStyle().Foreground(colorTextMuted).Render(timeStr),
			scoreBadge,
			lipgloss.NewStyle().Foreground(colorCyberCyan).Render(ev.NodeID),
			lipgloss.NewStyle().Bold(true).Foreground(colorTextLight).Render(ev.ClientIP),
			lipgloss.NewStyle().Foreground(colorWarningGold).Render(techStr),
			lipgloss.NewStyle().Foreground(colorTextMuted).Render(truncateString(ev.RawLine, width-4)),
		)
		b.WriteString(line + "\n")
	}
	return b.String()
}

func (m *SIEMModel) renderMITREPanel(width int) string {
	var b strings.Builder
	b.WriteString(matrixTitleStyle.Render("🛡 MITRE ATT&CK HEATMAP") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	if len(m.mitreMap) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("Awaiting technique signatures...\n"))
		return b.String()
	}

	// Known core techniques display
	coreTechniques := []string{"T1190", "T1059.004", "T1595.002", "T1110.001", "T1027", "T1552.005"}
	for _, tech := range coreTechniques {
		cnt := m.mitreMap[tech]
		bars := strings.Repeat("█", min(cnt/2+1, 10))
		if cnt == 0 {
			bars = "░"
		}
		b.WriteString(fmt.Sprintf("%-10s %s %d\n",
			lipgloss.NewStyle().Foreground(colorWarningGold).Render(tech),
			lipgloss.NewStyle().Foreground(colorAlertPink).Render(bars),
			cnt))
	}

	// Extra detected techniques
	for tech, cnt := range m.mitreMap {
		isCore := false
		for _, c := range coreTechniques {
			if c == tech {
				isCore = true
				break
			}
		}
		if !isCore && cnt > 0 {
			bars := strings.Repeat("█", min(cnt/2+1, 10))
			b.WriteString(fmt.Sprintf("%-10s %s %d\n",
				lipgloss.NewStyle().Foreground(colorCyberCyan).Render(tech),
				lipgloss.NewStyle().Foreground(colorNeonGreen).Render(bars),
				cnt))
		}
	}

	return b.String()
}

func (m *SIEMModel) renderBottomPanel(width int) string {
	var sparkline strings.Builder
	for _, val := range m.rateHistory {
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

	shortcuts := lipgloss.NewStyle().Foreground(colorCyberCyan).Render("[B] Fleet Ban IP  |  [U] Unban IP  |  [Tab] Switch Panel  |  [Q] Quit")
	rateDisplay := lipgloss.NewStyle().Bold(true).Foreground(colorNeonGreen).Render(fmt.Sprintf("Stream Rate: [ %d EPS | Total: %s ]", eps, strconv.FormatUint(total, 10)))
	graph := lipgloss.NewStyle().Foreground(colorCyberCyan).Render(fmt.Sprintf("[%s]", sparkline.String()))

	status := m.statusPrompt
	if status != "" {
		status = alertStyle.Render(" " + status)
	}

	return fmt.Sprintf("%s   %s %s%s\n%s", shortcuts, rateDisplay, graph, status,
		lipgloss.NewStyle().Foreground(colorTextMuted).Render("CoPSeC Autonomous Defense Core • Pure Zero-Leak Async Architecture"))
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
