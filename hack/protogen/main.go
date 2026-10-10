// Command protogen generates Go code for the protobuf schemas under api/
// without protoc: protocompile parses the schema and protoc-gen-go's own
// generator writes the code. It is a separate module so that the
// repository's go.mod carries no build-time-only dependency.
//
// Usage (from the repository root):
//
//	go run -C hack/protogen . ../../api mtcp/v1/mtcp.proto
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bufbuild/protocompile"
	gengo "google.golang.org/protobuf/cmd/protoc-gen-go/internal_gengo"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "protogen:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: protogen <import root> <file.proto>...")
	}
	root, names := args[0], args[1:]
	compiler := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{ImportPaths: []string{root}}),
	}
	files, err := compiler.Compile(context.Background(), names...)
	if err != nil {
		return err
	}
	request := &pluginpb.CodeGeneratorRequest{
		FileToGenerate: names,
		Parameter:      proto.String("paths=source_relative"),
	}
	for _, file := range files {
		request.ProtoFile = append(request.ProtoFile, protodesc.ToFileDescriptorProto(file))
	}
	sortDependenciesFirst(request.ProtoFile)
	plugin, err := protogen.Options{}.New(request)
	if err != nil {
		return err
	}
	for _, file := range plugin.Files {
		if file.Generate {
			gengo.GenerateFile(plugin, file)
		}
	}
	response := plugin.Response()
	if response.Error != nil {
		return errors.New(response.GetError())
	}
	for _, generated := range response.File {
		path := filepath.Join(root, generated.GetName())
		if err := os.WriteFile(path, []byte(generated.GetContent()), 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", path)
	}
	return nil
}

// sortDependenciesFirst keeps the request valid when a schema imports another
// one: protogen requires every file to follow its dependencies.
func sortDependenciesFirst(files []*descriptorpb.FileDescriptorProto) {
	byName := make(map[string]*descriptorpb.FileDescriptorProto, len(files))
	for _, file := range files {
		byName[file.GetName()] = file
	}
	sorted := make([]*descriptorpb.FileDescriptorProto, 0, len(files))
	seen := make(map[string]bool, len(files))
	var visit func(*descriptorpb.FileDescriptorProto)
	visit = func(file *descriptorpb.FileDescriptorProto) {
		if seen[file.GetName()] {
			return
		}
		seen[file.GetName()] = true
		for _, dependency := range file.GetDependency() {
			if next, ok := byName[dependency]; ok {
				visit(next)
			}
		}
		sorted = append(sorted, file)
	}
	for _, file := range files {
		visit(file)
	}
	copy(files, sorted)
}
