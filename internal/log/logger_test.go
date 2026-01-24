package log

import (
	"bytes"
	"testing"

	"github.com/caarlos0/log"
)

func TestNoopLogger(t *testing.T) {
	t.Parallel()

	logger := NewNoopLogger()

	// All these operations should do nothing and not panic
	logger.Debug("test")
	logger.Debugf("test %s", "arg")
	logger.Info("test")
	logger.Infof("test %s", "arg")
	logger.Warn("test")
	logger.Warnf("test %s", "arg")
	logger.Error("test")
	logger.Errorf("test %s", "arg")
	logger.WithField("key", "value").Info("test")
	logger.WithError(nil).Error("test")
	logger.IncreasePadding()
	logger.DecreasePadding()
	logger.ResetPadding()
}

func TestLoggerAdapter(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	stdLogger := log.New(buf)
	logger := NewLogger(stdLogger)

	logger.Info("test message")

	output := buf.String()
	if output == "" {
		t.Error("expected logger to produce output, got empty string")
	}
	if !bytes.Contains(buf.Bytes(), []byte("test message")) {
		t.Errorf("expected output to contain 'test message', got: %s", output)
	}
}

func TestLoggerAdapterWithField(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	stdLogger := log.New(buf)
	logger := NewLogger(stdLogger)

	logger.WithField("key", "value").Info("test")

	output := buf.String()
	if output == "" {
		t.Error("expected logger to produce output, got empty string")
	}
	if !bytes.Contains(buf.Bytes(), []byte("test")) {
		t.Errorf("expected output to contain 'test', got: %s", output)
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("default logger", func(t *testing.T) {
		t.Parallel()

		buf := &bytes.Buffer{}
		logger := New(WithOutput(buf))

		logger.Info("test message")

		output := buf.String()
		if output == "" {
			t.Error("expected logger to produce output, got empty string")
		}
		if !bytes.Contains(buf.Bytes(), []byte("test message")) {
			t.Errorf("expected output to contain 'test message', got: %s", output)
		}
	})

	t.Run("noop logger", func(t *testing.T) {
		t.Parallel()

		buf := &bytes.Buffer{}
		logger := New(WithNoop(), WithOutput(buf))

		logger.Info("test message")

		output := buf.String()
		if output != "" {
			t.Errorf("expected noop logger to produce no output, got: %s", output)
		}
	})

	t.Run("verbose logger", func(t *testing.T) {
		t.Parallel()

		buf := &bytes.Buffer{}
		logger := New(WithVerbose(true), WithOutput(buf))

		logger.Debug("debug message")

		output := buf.String()
		if output == "" {
			t.Error("expected verbose logger to produce output for debug messages, got empty string")
		}
		if !bytes.Contains(buf.Bytes(), []byte("debug message")) {
			t.Errorf("expected output to contain 'debug message', got: %s", output)
		}
	})

	t.Run("non-verbose logger ignores debug", func(t *testing.T) {
		t.Parallel()

		buf := &bytes.Buffer{}
		logger := New(WithVerbose(false), WithOutput(buf))

		logger.Debug("debug message")

		output := buf.String()
		if output != "" {
			t.Errorf("expected non-verbose logger to ignore debug messages, got: %s", output)
		}
	})
}
