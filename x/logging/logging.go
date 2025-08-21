package logging

import (
	"context"
	"errors"
	"log"
	"os"
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
	d.logger.Printf(d.prefix+format, v...)
}

func (d defaultLogger) Warnf(format string, v ...interface{}) {
	d.logger.Printf("[WARN] "+d.prefix+format, v...)
}

func (d defaultLogger) Errorf(format string, v ...interface{}) {
	d.logger.Printf("[ERR] "+d.prefix+format, v...)
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
