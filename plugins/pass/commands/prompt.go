// Copyright 2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

var (
	errEmptyValue     = errors.New("no value entered")
	errMultilinePaste = errors.New("pasted value spans several lines; pipe it via STDIN instead")
)

func unwrapFile(s any) (*os.File, bool) {
	// Under `docker pass`, plugin.Run makes cobra's in and out docker's
	// streams.In and streams.Out, which hide the file behind File().
	if d, wrapped := s.(interface{ File() (*os.File, bool) }); wrapped {
		return d.File()
	}
	f, ok := s.(*os.File)
	return f, ok
}

func secretFromPrompt(ctx context.Context, in *os.File, out io.Writer, id string) (*secret, error) {
	if f, ok := unwrapFile(out); ok {
		out = f // bubbletea sizes and restores the terminal through the file
	}
	p := tea.NewProgram(newPromptModel(id),
		tea.WithContext(ctx),
		tea.WithInput(in),
		tea.WithOutput(out),
		tea.WithoutSignalHandler(), // the root already cancels ctx on SIGINT/SIGTERM
	)
	returnModel, err := p.Run()
	m, ok := returnModel.(promptModel)
	switch {
	case errors.Is(err, tea.ErrInterrupted):
		// In raw mode Ctrl-C is a key press, not a signal. Report it as the
		// cancellation it is so the root exits 130 without a message.
		return nil, context.Canceled
	case errors.Is(err, tea.ErrProgramKilled) && ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		return nil, err
	case !ok:
		return nil, fmt.Errorf("unexpected prompt model %T", returnModel)
	case m.err != nil:
		return nil, m.err
	}
	return &secret{id: id, val: m.input.Value()}, nil
}

type promptModel struct {
	input textinput.Model
	err   error
}

func newPromptModel(id string) promptModel {
	ti := textinput.New()
	ti.Prompt = fmt.Sprintf("Enter secret for %s: ", id)
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '*'
	ti.Focus()
	return promptModel{input: ti}
}

func (m promptModel) Init() tea.Cmd { return textinput.Blink }

func (m promptModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Interrupt
		case "enter":
			if m.input.Value() == "" {
				m.err = errEmptyValue
			}
			return m, tea.Quit
		}
	case tea.PasteMsg:
		content := strings.TrimRight(msg.Content, "\r\n")
		if strings.ContainsAny(content, "\r\n") {
			m.err = errMultilinePaste
			return m, tea.Quit
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(tea.PasteMsg{Content: content})
		return m, cmd
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m promptModel) View() tea.View {
	return tea.NewView(m.input.View() + "\n")
}
