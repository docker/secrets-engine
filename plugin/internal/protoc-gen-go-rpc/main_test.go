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

package main

import (
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"

	_ "github.com/docker/secrets-engine/client/api/health/v1"
	_ "github.com/docker/secrets-engine/client/api/plugins/v1"
	_ "github.com/docker/secrets-engine/client/api/resolver/v1"
	_ "github.com/docker/secrets-engine/plugin/api/accesscontrol/v1"
	_ "github.com/docker/secrets-engine/plugin/api/plugins/v1"
)

// apiDir is the directory that buf.gen.yaml makes the generator write to.
const apiDir = "../../api"

const (
	clientModulePath = "github.com/docker/secrets-engine/client"
	clientAPIDir     = "../../../client/api"
)

func run(t *testing.T, req *pluginpb.CodeGeneratorRequest) *pluginpb.CodeGeneratorResponse {
	t.Helper()
	opts, clientModule := options()
	plugin, err := opts.New(req)
	require.NoError(t, err)
	if err := generate(plugin, *clientModule); err != nil {
		plugin.Error(err)
	}
	return plugin.Response()
}

// tokens returns the Go tokens of src, which leaves out comments and white space.
func tokens(src []byte) []string {
	fset := token.NewFileSet()
	var s scanner.Scanner
	s.Init(fset.AddFile("", fset.Base(), len(src)), src, nil, 0)
	var out []string
	for {
		_, tok, lit := s.Scan()
		switch tok {
		case token.EOF:
			return out
		case token.SEMICOLON:
			lit = ""
		}
		out = append(out, strings.TrimSpace(tok.String()+" "+lit))
	}
}

// TestCommittedStubsAreCurrent generates the stubs from the descriptors that
// the message packages register, and compares them with the files in
// plugin/api. Those descriptors carry no comments, so comments are left out.
func TestCommittedStubsAreCurrent(t *testing.T) {
	compareWithCommitted(t, "paths=source_relative", apiDir)
}

func TestCommittedClientStubsAreCurrent(t *testing.T) {
	files := compareWithCommitted(t, "paths=source_relative,client_module="+clientModulePath, clientAPIDir)
	var names []string
	for _, file := range files {
		names = append(names, file.GetName())
		assert.NotContains(t, file.GetContent(), "Handler")
		assert.NotContains(t, file.GetContent(), "github.com/docker/secrets-engine/plugin")
	}
	assert.ElementsMatch(t, []string{
		"health/v1/healthv1rpc/api.rpc.go",
		"plugins/v1/pluginsv1rpc/management.rpc.go",
		"resolver/v1/resolverv1rpc/api.rpc.go",
	}, names)
}

func compareWithCommitted(t *testing.T, parameter, dir string) []*pluginpb.CodeGeneratorResponse_File {
	t.Helper()
	req := &pluginpb.CodeGeneratorRequest{Parameter: proto.String(parameter)}
	seen := map[string]bool{}
	var add func(protoreflect.FileDescriptor)
	add = func(file protoreflect.FileDescriptor) {
		if seen[file.Path()] {
			return
		}
		seen[file.Path()] = true
		for i := range file.Imports().Len() {
			add(file.Imports().Get(i).FileDescriptor)
		}
		req.ProtoFile = append(req.ProtoFile, protodesc.ToFileDescriptorProto(file))
		if !strings.HasPrefix(file.Path(), "google/") {
			req.FileToGenerate = append(req.FileToGenerate, file.Path())
		}
	}
	protoregistry.GlobalFiles.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		add(file)
		return true
	})

	resp := run(t, req)
	require.Empty(t, resp.GetError())
	assert.NotZero(t, resp.GetSupportedFeatures()&uint64(pluginpb.CodeGeneratorResponse_FEATURE_SUPPORTS_EDITIONS))
	generated := map[string]bool{}
	for _, file := range resp.GetFile() {
		generated[file.GetName()] = true
		committed, err := os.ReadFile(filepath.Join(dir, file.GetName()))
		require.NoError(t, err)
		assert.Equalf(t, tokens([]byte(file.GetContent())), tokens(committed), "%s is stale: run make proto-generate", file.GetName())
	}
	require.NoError(t, filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".rpc.go") {
			name, _ := filepath.Rel(dir, path)
			assert.Truef(t, generated[filepath.ToSlash(name)], "%s: this test lacks the descriptor: import the message package", name)
		}
		return err
	}))
	return resp.GetFile()
}

func TestRejectsStreamingRPCs(t *testing.T) {
	file := &descriptorpb.FileDescriptorProto{
		Name:        proto.String("events/v1/api.proto"),
		Syntax:      proto.String("proto3"),
		Package:     proto.String("events.v1"),
		Options:     &descriptorpb.FileOptions{GoPackage: proto.String("example.com/events/v1;eventsv1")},
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Event")}},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("EventService"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:            proto.String("Watch"),
				InputType:       proto.String(".events.v1.Event"),
				OutputType:      proto.String(".events.v1.Event"),
				ServerStreaming: proto.Bool(true),
			}},
		}},
	}
	resp := run(t, &pluginpb.CodeGeneratorRequest{
		FileToGenerate: []string{file.GetName()},
		ProtoFile:      []*descriptorpb.FileDescriptorProto{file},
	})
	assert.Equal(t, "events/v1/api.proto: events.v1.EventService.Watch is a streaming RPC: only unary RPCs are supported", resp.GetError())
	assert.Empty(t, resp.GetFile())
}
