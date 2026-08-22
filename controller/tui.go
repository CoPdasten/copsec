package main

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Cyberpunk / Matrix Color Palette
var (
	colorNeonGreen  = lipgloss.Color("#00FF66")
	colorCyberCyan   = lipgloss.Color("#00F0FF")
	colorAlertPink   = lipgloss.Color("#FF0055")
	colorWarningGold = lipgloss.Color("#FFB800")
	colorDarkBg      = lipgloss.Color("#0A0E14")
	colorPanelBorder = lipgloss.Color("#1E293B")
	colorTextMuted   = lipgloss.Color("#64748B")
	colorTextLight   = lipgloss.Color("#E2E8F0")

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
)

type tickMsg time.Time
type eventMsg *StoredEvent

// SIEMModel holds state for the bubbletea TUI dashboard.
type SIEMModel struct {
	server       *CentralServer
	storage      *StorageEngine
	width        int
	height       int
	events       []*StoredEvent
	nodes        []NodeSession
	mitreStats   []MITREStat
	eventChan    <-chan *StoredEvent
	activeTab    int
	rateHistory  []int
	statusPrompt string
}

// NewSIEMModel creates a new TUI dashboard model.
func NewSIEMModel(server *CentralServer, storage *StorageEngine) *SIEMModel {
	return &SIEMModel{
		server:      server,
		storage:     storage,
		eventChan:   server.SubscribeEvents(),
		rateHistory: make([]int, 20),
	}
}

func (m *SIEMModel) Init() tea.Cmd {
	return tea.Batch(
		m.waitForEvent(),
		m.tickCmd(),
	)
}

func (m *SIEMModel) waitForEvent() tea.Cmd {
	return func() tea.Msg {
		ev := <-m.eventChan
		return eventMsg(ev)
	}
}

func (m *SIEMModel) tickCmd() tea.Cmd {
	return tea.Tick(1*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *SIEMModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.activeTab = (m.activeTab + 1) % 3
		case "b":
			m.statusPrompt = "[SOAR] Manual Global Ban Triggered"
		case "u":
			m.statusPrompt = "[SOAR] Manual Unban Triggered"
		case "c":
			m.statusPrompt = ""
		}

	case eventMsg:
		ev := (*StoredEvent)(msg)
		m.events = append([]*StoredEvent{ev}, m.events...)
		if len(m.events) > 50 {
			m.events = m.events[:50]
		}
		if len(m.rateHistory) > 0 {
			m.rateHistory[len(m.rateHistory)-1]++
		}
		cmds = append(cmds, m.waitForEvent())

	case tickMsg:
		m.nodes = m.server.GetNodesSnapshot()
		if stats, err := m.storage.GetMITREStats(); err == nil {
			m.mitreStats = stats
		}
		// Shift sparkline history
		m.rateHistory = append(m.rateHistory[1:], 0)
		cmds = append(cmds, m.tickCmd())
	}

	return m, tea.Batch(cmds...)
}

func (m *SIEMModel) View() string {
	if m.width == 0 {
		return "Initializing CoPSeC Matrix Dashboard..."
	}

	// Layout Calculations
	totalWidth := m.width - 4
	if totalWidth < 80 {
		totalWidth = 80
	}
	leftWidth := totalWidth * 25 / 100
	rightWidth := totalWidth * 25 / 100
	centerWidth := totalWidth - leftWidth - rightWidth - 6

	mainHeight := m.height - 10
	if mainHeight < 12 {
		mainHeight = 12
	}

	// 1. Top Banner
	banner := headerStyle.Render("⚡ CoPSeC ENTERPRISE MICRO-SIEM CONTROLLER") + " " +
		matrixTitleStyle.Render("v2.0 [CYBERPUNK MATRIX]") + "\n"

	// 2. Left Panel: Fleet / Nodes
	leftContent := m.renderFleetPanel(leftWidth - 2)
	leftPanel := panelStyle.Width(leftWidth).Height(mainHeight).Render(leftContent)

	// 3. Center Panel: Live Threat Stream
	centerContent := m.renderThreatStream(centerWidth - 2)
	centerPanel := activePanelStyle.Width(centerWidth).Height(mainHeight).Render(centerContent)

	// 4. Right Panel: MITRE ATT&CK Matrix
	rightContent := m.renderMITREPanel(rightWidth - 2)
	rightPanel := panelStyle.Width(rightWidth).Height(mainHeight).Render(rightContent)

	middleRow := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, centerPanel, rightPanel)

	// 5. Bottom Panel: Metrics & Controls
	bottomContent := m.renderBottomPanel(totalWidth)
	bottomPanel := panelStyle.Width(totalWidth).Height(4).Render(bottomContent)

	return lipgloss.JoinVertical(lipgloss.Left, banner, middleRow, bottomPanel)
}

func (m *SIEMModel) renderFleetPanel(width int) string {
	var b strings.Builder
	b.WriteString(matrixTitleStyle.Render("🌐 FLEET NODES") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	if len(m.nodes) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("No active nodes connected\n"))
		return b.String()
	}

	for _, n := range m.nodes {
		statusIcon := "🟢"
		if time.Since(n.LastSeen) > 30*time.Second {
			statusIcon = "🔴"
		}

		nodeName := n.NodeID
		if len(nodeName) > 14 {
			nodeName = nodeName[:14]
		}

		b.WriteString(fmt.Sprintf("%s %s\n", statusIcon, lipgloss.NewStyle().Bold(true).Foreground(colorTextLight).Render(nodeName)))
		b.WriteString(fmt.Sprintf("   CPU: %0.1f%% | RAM: %0.1f MB\n", n.CPUUsage, n.MemoryUsage))
		b.WriteString(fmt.Sprintf("   Bans: %d | Up: %ds\n", n.ActiveBansCount, n.UptimeSeconds))
		b.WriteString("\n")
	}
	return b.String()
}

func (m *SIEMModel) renderThreatStream(width int) string {
	var b strings.Builder
	b.WriteString(headerStyle.Render("⚡ REAL-TIME THREAT INGESTION STREAM") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render(strings.Repeat("─", width)) + "\n")

	if len(m.events) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("Listening for edge node stream events on gRPC...\n"))
		return b.String()
	}

	for i, ev := range m.events {
		if i >= 10 {
			break
		}

		timeStr := time.UnixMilli(ev.TimestampMs).Format("15:04:05")
		scoreBadge := lipgloss.NewStyle().Foreground(colorNeonGreen).Render(fmt.Sprintf("[%d]", ev.ThreatScore))
		if ev.ThreatScore >= 40 {
			scoreBadge = alertStyle.Render(fmt.Sprintf("[CRIT %d]", ev.ThreatScore))
		}

		line := fmt.Sprintf("%s %s %s 🎯 %s 🏷 %s\n   %s",
			lipgloss.NewStyle().Foreground(colorTextMuted).Render(timeStr),
			scoreBadge,
			lipgloss.NewStyle().Foreground(colorCyberCyan).Render(ev.NodeID),
			lipgloss.NewStyle().Bold(true).Foreground(colorTextLight).Render(ev.ClientIP),
			lipgloss.NewStyle().Foreground(colorWarningGold).Render(ev.MitreTechniqueID),
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

	if len(m.mitreStats) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(colorTextMuted).Render("Awaiting technique hits...\n"))
		return b.String()
	}

	for _, st := range m.mitreStats {
		bars := strings.Repeat("█", min(st.Count, 12))
		b.WriteString(fmt.Sprintf("%-10s %s %d\n",
			lipgloss.NewStyle().Foreground(colorWarningGold).Render(st.TechniqueID),
			lipgloss.NewStyle().Foreground(colorAlertPink).Render(bars),
			st.Count))
	}
	return b.String()
}

func (m *SIEMModel) renderBottomPanel(width int) string {
	var sparkline strings.Builder
	for _, val := range m.rateHistory {
		if val == 0 {
			sparkline.WriteString(" ")
		} else if val < 5 {
			sparkline.WriteString("▃")
		} else if val < 15 {
			sparkline.WriteString("▅")
		} else {
			sparkline.WriteString("█")
		}
	}

	shortcuts := lipgloss.NewStyle().Foreground(colorCyberCyan).Render("[B] Fleet Ban IP  |  [U] Unban  |  [Tab] Switch View  |  [Q] Quit")
	graph := lipgloss.NewStyle().Foreground(colorNeonGreen).Render(fmt.Sprintf("Stream Rate: [%s]", sparkline.String()))

	status := m.statusPrompt
	if status != "" {
		status = alertStyle.Render(" " + status)
	}

	return fmt.Sprintf("%s    %s%s\n%s", shortcuts, graph, status,
		lipgloss.NewStyle().Foreground(colorTextMuted).Render("CoPSeC Centralized SOAR Controller • Pure Zero-Leak Golang Architecture"))
}
