package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type screen int

const (
	screenList screen = iota
	screenConfig
)

// focusArea is which of the two stacked left-side panels has the keyboard.
type focusArea int

const (
	focusProject focusArea = iota // top 1/3: project / scope picker
	focusTool                     // bottom 2/3: tool list + configurator
)

// projMode is the sub-state of the project panel.
type projMode int

const (
	projList  projMode = iota // navigating the project list
	projName                  // typing a new project's name
	projScope                 // editing a project's in/out-of-scope entries
)

var (
	accent = lipgloss.Color("37")  // teal
	dim    = lipgloss.Color("244") // grey
	good   = lipgloss.Color("42")  // green
	warn   = lipgloss.Color("214") // amber
	bg     = lipgloss.Color("236")
	purple = lipgloss.Color("30") // panel borders (teal)

	mainBorderStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(purple)
	outBorderStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(purple)
	outTitleStyle   = lipgloss.NewStyle().Bold(true).Foreground(purple)
	// A focused panel keeps the purple border; a blurred one dims to grey.
	panelBlurStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(dim)

	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Padding(0, 1)
	flagSelStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(bg)
	flagStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	descStyle    = lipgloss.NewStyle().Foreground(dim).Italic(true)
	onStyle      = lipgloss.NewStyle().Foreground(good).Bold(true)
	offStyle     = lipgloss.NewStyle().Foreground(dim)
	reqStyle     = lipgloss.NewStyle().Foreground(warn)
	cmdBoxStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(accent).Padding(0, 1)
	cmdTextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("228"))
	helpStyle    = lipgloss.NewStyle().Foreground(dim)
	statusStyle  = lipgloss.NewStyle().Foreground(good).Bold(true)
)

type model struct {
	screen screen

	list list.Model

	tool   Tool // working copy being configured
	cursor int  // index into tool.Flags
	input  textinput.Model
	status string // transient message (e.g. "copied!")

	width, height int
	// panel geometry, recomputed on every resize.
	leftW, rightW, panelH  int
	projPanelH, toolPanelH int
	innerLeftW             int

	// left-top panel: project / scope picker.
	focus       focusArea
	projMode    projMode
	projects    []Project
	projCursor  int             // highlighted project in the list
	activeProj  int             // selected project in effect, -1 if none
	pinput      textinput.Model // project name / scope entry editor
	scopeBucket int             // 0 = in-scope, 1 = out-of-scope (while editing)
	scopeCursor int             // highlighted entry within the current bucket
	scopeFill   int             // rotating index for "fill field from scope"

	// right panel: live command output.
	vp      viewport.Model
	out     []string           // accumulated output lines
	outCh   chan outMsg        // streamed lines from the running command
	running bool               // a command is currently executing
	cancel  context.CancelFunc // cancels the running command

	// finalCmd is printed to stdout when the program quits.
	finalCmd string
}

func newModel() model {
	items := make([]list.Item, len(catalog))
	for i, t := range catalog {
		items[i] = t
	}

	d := list.NewDefaultDelegate()
	d.Styles.SelectedTitle = d.Styles.SelectedTitle.Foreground(accent).BorderForeground(accent)
	d.Styles.SelectedDesc = d.Styles.SelectedDesc.Foreground(lipgloss.Color("250")).BorderForeground(accent)

	l := list.New(items, d, 0, 0)
	l.Title = "Web — pick a tool"
	l.Styles.Title = titleStyle
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)
	// Advertise the way back up to the project panel in the list's help line.
	l.AdditionalShortHelpKeys = func() []key.Binding {
		return []key.Binding{
			key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("shift+tab", "projects")),
		}
	}

	ti := textinput.New()
	ti.Prompt = "› "
	ti.CharLimit = 512

	pi := textinput.New()
	pi.Prompt = "› "
	pi.CharLimit = 512

	vp := viewport.New(0, 0)
	vp.SetContent(helpStyle.Render("run a command with ctrl+r to see its output here"))

	projects := loadProjects()
	active := -1
	if len(projects) > 0 {
		active = 0
	}

	return model{
		screen:     screenList,
		list:       l,
		input:      ti,
		pinput:     pi,
		vp:         vp,
		projects:   projects,
		activeProj: active,
		focus:      focusProject,
	}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		// Left/right split 50/50; the left half is stacked 1/3 project over
		// 2/3 tool, with the output panel filling the right half.
		m.leftW = msg.Width / 2
		m.rightW = msg.Width - m.leftW
		m.panelH = msg.Height
		m.projPanelH = maxInt(5, msg.Height/3)
		m.toolPanelH = maxInt(5, msg.Height-m.projPanelH)

		m.innerLeftW = maxInt(10, m.leftW-2) // minus the panel border
		toolInnerH := maxInt(3, m.toolPanelH-2)
		m.list.SetSize(m.innerLeftW, toolInnerH)
		m.input.Width = maxInt(8, m.innerLeftW-28)
		m.pinput.Width = maxInt(8, m.innerLeftW-12)

		m.vp.Width = maxInt(10, m.rightW-2)
		m.vp.Height = maxInt(2, (m.panelH-2)-1) // minus the panel's title line
		return m, nil
	case outMsg:
		return m.handleOut(msg)
	case tea.MouseMsg:
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd
	case tea.KeyMsg:
		// ctrl+p jumps to the project panel from anywhere (except mid-edit).
		if msg.String() == "ctrl+p" && m.projMode == projList {
			m.focus = focusProject
			return m, nil
		}
		if m.focus == focusProject {
			return m.updateProject(msg)
		}
		if m.screen == screenList {
			return m.updateList(msg)
		}
		return m.updateConfig(msg)
	}
	// Non-key messages only matter to the list on the list screen.
	if m.screen == screenList {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Let the list own typing while its filter is active.
	if m.list.FilterState() == list.Filtering {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	switch msg.String() {
	case "ctrl+c", "q":
		if msg.String() == "ctrl+c" && m.running && m.cancel != nil {
			m.cancel()
			return m, nil
		}
		return m, tea.Quit
	case "shift+tab":
		// Mirror the project panel's "tab tools": step back up to projects.
		m.focus = focusProject
		return m, nil
	case "esc":
		// esc also backs out to the project panel. While a filter is applied
		// (not actively typing — that's handled above), let the list clear it
		// instead by falling through to list.Update below.
		if m.list.FilterState() == list.Unfiltered {
			m.focus = focusProject
			return m, nil
		}
	case "pgup", "pgdown", "home", "end":
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd
	case "enter":
		if sel, ok := m.list.SelectedItem().(Tool); ok {
			m.tool = sel.clone()
			m.cursor = 0
			m.status = ""
			m.prefillTarget() // seed the URL/host flag from the project scope
			m.syncInput()
			m.screen = screenConfig
		}
		return m, nil
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m model) updateConfig(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Some tools (e.g. the bare GTFOBins shell spawns) carry no flags: there is
	// nothing to configure, just a command to copy or run.
	if len(m.tool.Flags) == 0 {
		return m.updateConfigNoFlags(msg)
	}
	cur := &m.tool.Flags[m.cursor]
	isText := cur.Kind == KindString || cur.Kind == KindInt

	switch msg.String() {
	case "esc":
		m.screen = screenList
		m.status = ""
		return m, nil
	case "ctrl+c":
		if m.running && m.cancel != nil {
			m.cancel()
			m.status = "canceling…"
			return m, nil
		}
		return m, tea.Quit
	case "pgup", "pgdown", "home", "end":
		// Scroll the output panel without disturbing flag navigation.
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd
	case "ctrl+n":
		// Fill the selected text flag with the next in-scope target.
		if isText {
			if t := m.nextScopeTarget(); t != "" {
				cur.Value = t
				m.input.SetValue(t)
				m.input.CursorEnd()
				m.status = "filled from scope: " + t
			} else {
				m.status = "no in-scope targets — set them in the project panel (ctrl+p)"
			}
		}
		return m, nil
	case "shift+tab":
		// Step back up to the project panel, preserving the edited value.
		m.commitInput()
		m.focus = focusProject
		return m, nil
	case "up":
		m.commitInput()
		m.move(-1)
		return m, nil
	case "down", "tab":
		m.commitInput()
		m.move(1)
		return m, nil
	case " ":
		if cur.Kind == KindBool {
			cur.Enabled = !cur.Enabled
			m.status = ""
			return m, nil
		}
	case "left":
		if cur.Kind == KindChoice {
			m.cycleChoice(cur, -1)
			return m, nil
		}
	case "right":
		if cur.Kind == KindChoice {
			m.cycleChoice(cur, 1)
			return m, nil
		}
	case "ctrl+g":
		m.commitInput()
		if strings.TrimSpace(m.tool.Grep) == "" {
			m.status = "no key-info filter for this tool"
			return m, nil
		}
		m.tool.GrepOn = !m.tool.GrepOn
		if m.tool.GrepOn {
			m.status = "key-info filter ON — piping through: " + m.tool.Grep
		} else {
			m.status = "key-info filter off"
		}
		return m, nil
	case "ctrl+y":
		m.commitInput()
		cmd := m.tool.Command()
		m.finalCmd = cmd
		if err := clipboard.WriteAll(cmd); err != nil {
			m.status = "clipboard unavailable — command printed on exit (ctrl+o)"
		} else {
			m.status = "copied to clipboard ✓"
		}
		return m, nil
	case "ctrl+o":
		m.commitInput()
		m.finalCmd = m.tool.Command()
		return m, tea.Quit
	case "ctrl+r":
		m.commitInput()
		if miss := m.tool.MissingRequired(); len(miss) > 0 {
			m.status = "missing required: " + strings.Join(miss, ", ")
			return m, nil
		}
		if m.running {
			m.status = "a command is already running (ctrl+c to cancel)"
			return m, nil
		}
		cmd := m.tool.Command()
		if hit := m.outOfScopeHit(cmd); hit != "" {
			m.status = "blocked — command targets out-of-scope: " + hit
			return m, nil
		}
		m.finalCmd = cmd
		m.status = "running — output on the right (ctrl+c cancels)"
		return m, m.startRun(cmd)
	}

	// Remaining keys feed the text editor for value flags.
	if isText {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		cur.Value = m.input.Value()
		m.status = ""
		return m, cmd
	}
	return m, nil
}

// updateConfigNoFlags handles the config screen for a flag-less tool: there is
// nothing to navigate or edit, so only the command-level actions apply.
func (m model) updateConfigNoFlags(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "shift+tab":
		m.focus = focusProject
		return m, nil
	case "esc":
		m.screen = screenList
		m.status = ""
		return m, nil
	case "ctrl+c":
		if m.running && m.cancel != nil {
			m.cancel()
			m.status = "canceling…"
			return m, nil
		}
		return m, tea.Quit
	case "pgup", "pgdown", "home", "end":
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd
	case "ctrl+g":
		if strings.TrimSpace(m.tool.Grep) == "" {
			m.status = "no key-info filter for this tool"
			return m, nil
		}
		m.tool.GrepOn = !m.tool.GrepOn
		if m.tool.GrepOn {
			m.status = "key-info filter ON — piping through: " + m.tool.Grep
		} else {
			m.status = "key-info filter off"
		}
		return m, nil
	case "ctrl+y":
		cmd := m.tool.Command()
		m.finalCmd = cmd
		if err := clipboard.WriteAll(cmd); err != nil {
			m.status = "clipboard unavailable — command printed on exit (ctrl+o)"
		} else {
			m.status = "copied to clipboard ✓"
		}
		return m, nil
	case "ctrl+o":
		m.finalCmd = m.tool.Command()
		return m, tea.Quit
	case "ctrl+r":
		if m.running {
			m.status = "a command is already running (ctrl+c to cancel)"
			return m, nil
		}
		cmd := m.tool.Command()
		if hit := m.outOfScopeHit(cmd); hit != "" {
			m.status = "blocked — command targets out-of-scope: " + hit
			return m, nil
		}
		m.finalCmd = cmd
		m.status = "running — output on the right (ctrl+c cancels)"
		return m, m.startRun(cmd)
	}
	return m, nil
}

func (m *model) move(delta int) {
	n := len(m.tool.Flags)
	if n == 0 {
		return
	}
	m.cursor = (m.cursor + delta + n) % n
	m.syncInput()
	m.status = ""
}

// syncInput points the textinput at the currently selected flag (if editable).
func (m *model) syncInput() {
	if len(m.tool.Flags) == 0 {
		m.input.Blur()
		return
	}
	cur := m.tool.Flags[m.cursor]
	if cur.Kind == KindString || cur.Kind == KindInt {
		m.input.SetValue(cur.Value)
		m.input.Placeholder = cur.Placeholder
		m.input.CursorEnd()
		m.input.Focus()
	} else {
		m.input.Blur()
	}
}

// commitInput writes the editor's current value back to the selected flag.
func (m *model) commitInput() {
	cur := &m.tool.Flags[m.cursor]
	if cur.Kind == KindString || cur.Kind == KindInt {
		cur.Value = m.input.Value()
	}
}

func (m *model) cycleChoice(f *Flag, delta int) {
	if len(f.Choices) == 0 {
		return
	}
	idx := 0
	for i, c := range f.Choices {
		if c == f.Value {
			idx = i
			break
		}
	}
	idx = (idx + delta + len(f.Choices)) % len(f.Choices)
	f.Value = f.Choices[idx]
	m.status = ""
}

// refreshOut rewrites the output viewport from the accumulated lines and pins
// the view to the newest output.
func (m *model) refreshOut() {
	m.vp.SetContent(strings.Join(m.out, "\n"))
	m.vp.GotoBottom()
}

// handleOut folds a streamed output line (or the final exit notice) into the
// right panel and, unless the command has finished, keeps listening.
func (m model) handleOut(msg outMsg) (tea.Model, tea.Cmd) {
	if msg.final {
		m.running = false
		status := "— done · exit 0 —"
		if msg.err != nil {
			status = "— " + msg.err.Error() + " —"
		}
		m.out = append(m.out, "", statusStyle.Render(status))
		m.refreshOut()
		if m.status == "running — output on the right (ctrl+c cancels)" || m.status == "canceling…" {
			m.status = ""
		}
		return m, nil
	}
	// Bound memory on very chatty tools.
	if len(m.out) > 6000 {
		m.out = append(m.out[:1], m.out[len(m.out)-5000:]...)
	}
	m.out = append(m.out, msg.line)
	m.refreshOut()
	return m, waitForOut(m.outCh)
}

func (m model) View() string {
	if m.width == 0 {
		return "initializing…"
	}
	left := lipgloss.JoinVertical(lipgloss.Left, m.projectPanel(), m.toolPanel())
	return lipgloss.JoinHorizontal(lipgloss.Top, left, m.rightPanel())
}

// panelBorder returns the purple (focused) or dim (blurred) border style.
func panelBorder(active bool) lipgloss.Style {
	if active {
		return mainBorderStyle
	}
	return panelBlurStyle
}

// projectPanel is the top 1/3 of the left side: pick a project and its scope.
func (m model) projectPanel() string {
	return panelBorder(m.focus == focusProject).
		Width(m.leftW - 2).Height(m.projPanelH - 2).
		Render(m.projectView())
}

// toolPanel is the bottom 2/3 of the left side: the tool list or configurator.
func (m model) toolPanel() string {
	content := m.list.View()
	if m.screen == screenConfig {
		content = m.configView()
	}
	return panelBorder(m.focus == focusTool).
		Width(m.leftW - 2).Height(m.toolPanelH - 2).
		Render(content)
}

// rightPanel shows the live output of the last/running command.
func (m model) rightPanel() string {
	head := "output"
	if m.running {
		head = "output · running…"
	}
	content := outTitleStyle.Render(head) + "\n" + m.vp.View()
	return outBorderStyle.Width(m.rightW - 2).Height(m.panelH - 2).Render(content)
}

func (m model) configView() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render(fmt.Sprintf(" %s — %s ", m.tool.Name, m.tool.Desc)))
	b.WriteString("\n")
	if m.activeProj >= 0 && m.activeProj < len(m.projects) {
		b.WriteString(descStyle.Render("scope: "+m.projects[m.activeProj].Name) + "\n")
	}
	b.WriteString("\n")

	for i, f := range m.tool.Flags {
		selected := i == m.cursor
		cursor := "  "
		if selected {
			cursor = lipgloss.NewStyle().Foreground(accent).Render("▸ ")
		}

		label := f.label()
		if f.Required {
			label += reqStyle.Render(" *")
		}

		var val string
		switch f.Kind {
		case KindBool:
			if f.Enabled {
				val = onStyle.Render("[x] on")
			} else {
				val = offStyle.Render("[ ] off")
			}
		case KindChoice:
			val = fmt.Sprintf("‹ %s ›", f.Value)
		default:
			if selected {
				val = m.input.View()
			} else {
				val = flagStyle.Render(f.summary())
			}
		}

		line := fmt.Sprintf("%s%-26s %s", cursor, label, val)
		if selected {
			line = flagSelStyle.Render(line)
		}
		b.WriteString(line + "\n")

		if selected && f.Desc != "" {
			b.WriteString("    " + descStyle.Render(f.Desc) + "\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(m.commandBox())
	b.WriteString("\n")

	if m.status != "" {
		b.WriteString(statusStyle.Render(m.status) + "\n")
	}
	b.WriteString(helpStyle.Render(
		"↑/↓ move · space toggle · ←/→ choice · ctrl+n fill-from-scope · ctrl+g key-info filter · ctrl+y copy · ctrl+r run · shift+tab projects · esc back"))

	return b.String()
}

func (m model) commandBox() string {
	cmd := m.tool.Command()
	box := cmdBoxStyle.Width(maxInt(20, m.leftW-6))
	content := cmdTextStyle.Render(cmd)
	if missing := m.tool.MissingRequired(); len(missing) > 0 {
		content += "\n" + reqStyle.Render("missing required: "+strings.Join(missing, ", "))
	}
	if strings.TrimSpace(m.tool.Grep) != "" {
		state := "off"
		if m.tool.GrepOn {
			state = "on"
		}
		content += "\n" + helpStyle.Render("key-info filter ("+state+", ctrl+g): | "+m.tool.Grep)
	}
	return box.Render(content)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
