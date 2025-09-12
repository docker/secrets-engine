package logging

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
)

type Logger interface {
	Printf(format string, v ...interface{})
	Warnf(format string, v ...interface{})
	Errorf(format string, v ...interface{})
}

type defaultLogger struct {
	logger *log.Logger
	prefix string
}

func NewDefaultLogger(prefix string) Logger {
	if prefix != "" && !strings.HasSuffix(prefix, ": ") {
		prefix += ": "
	}
	return &defaultLogger{logger: log.New(os.Stderr, "", log.LstdFlags), prefix: prefix}
}

func (d defaultLogger) Printf(format string, v ...interface{}) {
	d.logger.Printf(suffix()+d.prefix+format, v...)
}

func (d defaultLogger) Warnf(format string, v ...interface{}) {
	d.logger.Printf(suffix()+"[WARN] "+d.prefix+format, v...)
}

func (d defaultLogger) Errorf(format string, v ...interface{}) {
	d.logger.Printf(suffix()+"[ERR] "+d.prefix+format+"\n"+stackTrace(), v...)
}

func suffix() string {
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		return ""
	}
	return fmt.Sprintf("[%s:%d] ", file, line) // Note: Additionally set -trimpath when building to not leak anything from the file path
}

// Similar to debug.Stack() except it skips the top 3 frames which include the logger itself
// to keep the logs focused on the actual relevant stack traces.
func stackTrace() string {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:]) // skip runtime.Callers + stackTrace
	if len(pcs) < n {
		return ""
	}
	frames := runtime.CallersFrames(pcs[:n])
	trace := ""
	for {
		frame, more := frames.Next()
		// Note: Additionally set -trimpath when building to not leak anything from the file path
		trace += fmt.Sprintf("%s\n\t%s:%d\n", frame.Function, frame.File, frame.Line)
		if !more {
			break
		}
	}
	return trace
}

type loggerKey struct{}

// WithLogger returns a new context with the provided logger.
func WithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// FromContext retrieves the current logger from the context. If no logger is
// available, a new default logger gets returned.
func FromContext(ctx context.Context) (Logger, error) {
	if logger, ok := ctx.Value(loggerKey{}).(Logger); ok {
		return logger, nil
	}
	return nil, errors.New("no logger found in context")
}
