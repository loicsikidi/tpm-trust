package log

import (
	"io"
	"os"

	"github.com/caarlos0/log"
)

// Logger is the interface for logging operations.
// This allows using different logger implementations, including a noop logger
// when internal logs must be muted (e.g., JSON or PEM format).
type Logger interface {
	Debug(msg string)
	Debugf(format string, args ...any)
	Info(msg string)
	Infof(format string, args ...any)
	Warn(msg string)
	Warnf(format string, args ...any)
	Error(msg string)
	Errorf(format string, args ...any)
	WithField(key string, value any) FieldLogger
	WithError(err error) FieldLogger
	IncreasePadding()
	DecreasePadding()
	ResetPadding()
}

// FieldLogger is the interface for logging with fields.
type FieldLogger interface {
	Debug(msg string)
	Debugf(format string, args ...any)
	Info(msg string)
	Infof(format string, args ...any)
	Warn(msg string)
	Warnf(format string, args ...any)
	Error(msg string)
	Errorf(format string, args ...any)
	WithField(key string, value any) FieldLogger
	WithError(err error) FieldLogger
}

// Ensure *log.Logger implements Logger interface.
var _ Logger = (*loggerAdapter)(nil)

// loggerAdapter wraps log.Logger to implement the Logger interface.
type loggerAdapter struct {
	*log.Logger
}

// NewLogger creates a new Logger from a log.Logger.
func NewLogger(l *log.Logger) Logger {
	return &loggerAdapter{Logger: l}
}

func (l *loggerAdapter) WithField(key string, value any) FieldLogger {
	return &fieldLoggerAdapter{Entry: l.Logger.WithField(key, value)}
}

func (l *loggerAdapter) WithError(err error) FieldLogger {
	return &fieldLoggerAdapter{Entry: l.Logger.WithError(err)}
}

// fieldLoggerAdapter wraps log.Entry to implement the FieldLogger interface.
type fieldLoggerAdapter struct {
	*log.Entry
}

func (f *fieldLoggerAdapter) WithField(key string, value any) FieldLogger {
	return &fieldLoggerAdapter{Entry: f.Entry.WithField(key, value)}
}

func (f *fieldLoggerAdapter) WithError(err error) FieldLogger {
	return &fieldLoggerAdapter{Entry: f.Entry.WithError(err)}
}

// noopLogger is a logger that does nothing.
// Used when we want clean output without internal logs (e.g., JSON/PEM format).
// It implements both Logger and FieldLogger interfaces.
type noopLogger struct{}

// NewNoopLogger creates a new noop logger that discards all log messages.
func NewNoopLogger() Logger {
	return &noopLogger{}
}

func (n *noopLogger) Debug(msg string)                            {}
func (n *noopLogger) Debugf(format string, args ...any)           {}
func (n *noopLogger) Info(msg string)                             {}
func (n *noopLogger) Infof(format string, args ...any)            {}
func (n *noopLogger) Warn(msg string)                             {}
func (n *noopLogger) Warnf(format string, args ...any)            {}
func (n *noopLogger) Error(msg string)                            {}
func (n *noopLogger) Errorf(format string, args ...any)           {}
func (n *noopLogger) WithField(key string, value any) FieldLogger { return n }
func (n *noopLogger) WithError(err error) FieldLogger             { return n }
func (n *noopLogger) IncreasePadding()                            {}
func (n *noopLogger) DecreasePadding()                            {}
func (n *noopLogger) ResetPadding()                               {}

// Ensure noopLogger implements both Logger and FieldLogger interfaces.
var _ Logger = (*noopLogger)(nil)
var _ FieldLogger = (*noopLogger)(nil)

// Option is a functional option for configuring a logger.
type Option func(*config)

type config struct {
	verbose bool
	noop    bool
	output  io.Writer
}

// WithVerbose enables debug level logging.
func WithVerbose(verbose bool) Option {
	return func(c *config) {
		c.verbose = verbose
	}
}

// WithNoop creates a noop logger that discards all output.
func WithNoop() Option {
	return func(c *config) {
		c.noop = true
	}
}

// WithOutput sets the output writer for the logger.
func WithOutput(w io.Writer) Option {
	return func(c *config) {
		c.output = w
	}
}

// New creates a new [Logger] with the given options.
// By default, it creates a logger that writes to stdout with info level.
//
// Example:
//
//	// Create a verbose logger
//	logger := log.New(log.WithVerbose(true))
//
//	// Create a noop logger for clean output
//	logger := log.New(log.WithNoop())
//
//	// Create a logger with custom output
//	logger := log.New(log.WithOutput(customWriter))
func New(opts ...Option) Logger {
	cfg := &config{
		output: os.Stdout,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.noop {
		return NewNoopLogger()
	}

	stdLogger := log.New(cfg.output)
	if cfg.verbose {
		stdLogger.Level = log.DebugLevel
	}

	return NewLogger(stdLogger)
}
