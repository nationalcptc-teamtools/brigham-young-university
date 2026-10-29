package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// Project is a hunting target: a name plus the in-scope targets you may test
// and the out-of-scope entries that must never appear in a command.
type Project struct {
	Name     string   `json:"name"`
	InScope  []string `json:"in_scope"`
	OutScope []string `json:"out_of_scope"`
}

// Projects are shared across every mode (web / AD / Linux / setup): an
// engagement and its scope are the same wherever you work, so they live in one
// file rather than one per mode. legacyProjectDirs are the old per-mode files,
// merged into the shared store once on first load so nothing created before the
// switch is lost.
const sharedProjectsDir = "pentest-suite"

var legacyProjectDirs = []string{"web", "active-directory", "linux", "setup"}

// projectsPath is where this app's projects persist, shared across all modes.
func projectsPath() string { return configProjectsPath(sharedProjectsDir) }

// configProjectsPath resolves a config sub-directory's projects.json.
func configProjectsPath(sub string) string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return sub + "-projects.json"
	}
	return filepath.Join(dir, sub, "projects.json")
}

// loadProjects reads the shared project list, returning nil if none exist. On
// first run (no shared file yet) it migrates any projects from the old per-mode
// files so a project created before the switch still shows up everywhere.
func loadProjects() []Project {
	if ps, ok := readProjects(projectsPath()); ok {
		return ps
	}
	merged := migrateLegacyProjects()
	if len(merged) > 0 {
		_ = saveProjectsList(merged)
	}
	return merged
}

// readProjects reads and parses a projects.json; ok is false when the file is
// absent or unreadable (so callers can tell "no file" from "empty list").
func readProjects(path string) (ps []Project, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	if err := json.Unmarshal(data, &ps); err != nil {
		return nil, false
	}
	return ps, true
}

// migrateLegacyProjects merges the pre-shared per-mode project files into one
// list, unioning the scopes of any projects that share a name.
func migrateLegacyProjects() []Project {
	var out []Project
	byName := map[string]int{}
	for _, sub := range legacyProjectDirs {
		ps, ok := readProjects(configProjectsPath(sub))
		if !ok {
			continue
		}
		for _, p := range ps {
			if i, seen := byName[p.Name]; seen {
				out[i].InScope = unionStrings(out[i].InScope, p.InScope)
				out[i].OutScope = unionStrings(out[i].OutScope, p.OutScope)
				continue
			}
			byName[p.Name] = len(out)
			out = append(out, p)
		}
	}
	return out
}

// unionStrings appends entries of b not already in a, preserving order.
func unionStrings(a, b []string) []string {
	for _, v := range b {
		if !contains(a, v) {
			a = append(a, v)
		}
	}
	return a
}

// saveProjects persists the current projects, best-effort.
func (m *model) saveProjects() { _ = saveProjectsList(m.projects) }

// saveProjectsList writes the shared project list to disk. Shared by the TUI
// and the --web server so both edit the same file across every mode.
func saveProjectsList(ps []Project) error {
	path := projectsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// updateProject handles keys while the project panel has focus.
func (m model) updateProject(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.projMode {
	case projName:
		switch msg.String() {
		case "esc":
			m.projMode = projList
			return m, nil
		case "enter":
			if name := strings.TrimSpace(m.pinput.Value()); name != "" {
				m.projects = append(m.projects, Project{Name: name})
				m.projCursor = len(m.projects) - 1
				m.activeProj = m.projCursor
				m.saveProjects()
			}
			m.projMode = projList
			return m, nil
		default:
			var cmd tea.Cmd
			m.pinput, cmd = m.pinput.Update(msg)
			return m, cmd
		}
	case projScope:
		return m.updateScope(msg)
	}

	// projList
	switch msg.String() {
	case "ctrl+c":
		if m.running && m.cancel != nil {
			m.cancel()
			return m, nil
		}
		return m, tea.Quit
	case "up", "k":
		if m.projCursor > 0 {
			m.projCursor--
		}
		return m, nil
	case "down", "j":
		if m.projCursor < len(m.projects)-1 {
			m.projCursor++
		}
		return m, nil
	case "enter":
		if len(m.projects) > 0 {
			m.activeProj = m.projCursor
			m.scopeFill = 0
			m.saveProjects()
		}
		m.focus = focusTool
		return m, nil
	case "tab", "esc":
		m.focus = focusTool
		return m, nil
	case "n":
		m.projMode = projName
		m.pinput.SetValue("")
		m.pinput.Placeholder = "project name"
		m.pinput.CursorEnd()
		m.pinput.Focus()
		return m, nil
	case "s":
		if len(m.projects) > 0 {
			m.projMode = projScope
			m.scopeBucket = 0
			m.scopeCursor = 0
			m.pinput.SetValue("")
			m.pinput.Placeholder = "add target, enter to save"
			m.pinput.Focus()
		}
		return m, nil
	case "d":
		if len(m.projects) > 0 {
			m.projects = append(m.projects[:m.projCursor], m.projects[m.projCursor+1:]...)
			if m.projCursor >= len(m.projects) {
				m.projCursor = maxInt(0, len(m.projects)-1)
			}
			if m.activeProj >= len(m.projects) {
				m.activeProj = len(m.projects) - 1
			}
			m.saveProjects()
		}
		return m, nil
	}
	return m, nil
}

// updateScope handles keys while editing a project's scope lists.
func (m model) updateScope(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	p := &m.projects[m.projCursor]
	switch msg.String() {
	case "esc":
		m.projMode = projList
		m.saveProjects()
		return m, nil
	case "ctrl+t":
		m.scopeBucket ^= 1 // toggle in-scope / out-of-scope
		m.scopeCursor = 0
		return m, nil
	case "enter":
		if v := strings.TrimSpace(m.pinput.Value()); v != "" {
			if m.scopeBucket == 0 {
				p.InScope = append(p.InScope, v)
			} else {
				p.OutScope = append(p.OutScope, v)
			}
			m.pinput.SetValue("")
			m.saveProjects()
		}
		return m, nil
	case "up":
		if m.scopeCursor > 0 {
			m.scopeCursor--
		}
		return m, nil
	case "down":
		if m.scopeCursor < len(*m.scopeList(p))-1 {
			m.scopeCursor++
		}
		return m, nil
	case "ctrl+x":
		list := m.scopeList(p)
		if m.scopeCursor < len(*list) {
			*list = append((*list)[:m.scopeCursor], (*list)[m.scopeCursor+1:]...)
			if m.scopeCursor >= len(*list) {
				m.scopeCursor = maxInt(0, len(*list)-1)
			}
			m.saveProjects()
		}
		return m, nil
	default:
		var cmd tea.Cmd
		m.pinput, cmd = m.pinput.Update(msg)
		return m, cmd
	}
}

// scopeList points at the slice for the bucket currently being edited.
func (m model) scopeList(p *Project) *[]string {
	if m.scopeBucket == 0 {
		return &p.InScope
	}
	return &p.OutScope
}

// projectView renders the top-left project/scope panel.
func (m model) projectView() string {
	var b strings.Builder
	b.WriteString(outTitleStyle.Render("projects"))
	b.WriteString("\n")

	switch m.projMode {
	case projName:
		b.WriteString("new project:\n")
		b.WriteString(m.pinput.View() + "\n")
		b.WriteString(helpStyle.Render("enter save · esc cancel"))
		return b.String()

	case projScope:
		p := &m.projects[m.projCursor]
		bucket := "in-scope"
		if m.scopeBucket == 1 {
			bucket = "out-of-scope"
		}
		b.WriteString(fmt.Sprintf("%s · [%s]\n", p.Name, onStyle.Render(bucket)))
		b.WriteString(m.pinput.View() + "\n")
		for i, e := range *m.scopeList(p) {
			cur := "  "
			if i == m.scopeCursor {
				cur = reqStyle.Render("▸ ")
			}
			b.WriteString(cur + e + "\n")
		}
		b.WriteString(helpStyle.Render("enter add · ctrl+t in/out · ↑/↓+ctrl+x del · esc done"))
		return b.String()
	}

	// projList
	if len(m.projects) == 0 {
		b.WriteString(descStyle.Render("no projects yet\n"))
		b.WriteString(helpStyle.Render("n new project"))
		return b.String()
	}
	for i, p := range m.projects {
		cur := "  "
		if i == m.projCursor {
			cur = reqStyle.Render("▸ ")
		}
		mark := " "
		if i == m.activeProj {
			mark = onStyle.Render("*")
		}
		b.WriteString(fmt.Sprintf("%s%s %s  %s\n", cur, mark, p.Name,
			descStyle.Render(fmt.Sprintf("(%d in / %d out)", len(p.InScope), len(p.OutScope)))))
	}
	b.WriteString(helpStyle.Render("↑/↓ · enter select · n new · s scope · d del · tab tools"))
	return b.String()
}

// prefillTarget seeds the tool's primary URL/host flag from the active
// project's first in-scope target (when that flag is still empty).
func (m *model) prefillTarget() {
	in := m.activeInScope()
	if len(in) == 0 {
		return
	}
	if idx := m.primaryTargetIdx(); idx >= 0 {
		if strings.TrimSpace(m.tool.Flags[idx].Value) == "" {
			m.tool.Flags[idx].Value = in[0]
		}
	}
	m.scopeFill = 0
}

// nextScopeTarget returns the next in-scope target, cycling through the list.
func (m *model) nextScopeTarget() string {
	in := m.activeInScope()
	if len(in) == 0 {
		return ""
	}
	t := in[m.scopeFill%len(in)]
	m.scopeFill++
	return t
}

// outOfScopeHit reports the first out-of-scope entry that appears in cmd.
func (m *model) outOfScopeHit(cmd string) string {
	if m.activeProj < 0 || m.activeProj >= len(m.projects) {
		return ""
	}
	for _, o := range m.projects[m.activeProj].OutScope {
		if o = strings.TrimSpace(o); o != "" && strings.Contains(cmd, o) {
			return o
		}
	}
	return ""
}

// activeInScope returns the in-scope list of the active project, or nil.
func (m *model) activeInScope() []string {
	if m.activeProj < 0 || m.activeProj >= len(m.projects) {
		return nil
	}
	return m.projects[m.activeProj].InScope
}

// primaryTargetIdx finds the flag most likely to hold the target URL/host:
// a required positional first, else a known target switch.
func (m *model) primaryTargetIdx() int {
	for i, f := range m.tool.Flags {
		if f.Positional && f.Required {
			return i
		}
	}
	targets := map[string]bool{
		"-u": true, "-d": true, "-h": true, "-host": true,
		"-l": true, "--targets": true, "-f": true,
	}
	for i, f := range m.tool.Flags {
		if targets[f.Flag] {
			return i
		}
	}
	return -1
}
