package logutil

import (
	"time"

	"github.com/loicsikidi/tpm-trust/internal/log"
)

func LogDuration(logger log.Logger, start time.Time) {
	logger.IncreasePadding()
	logger.Infof("took: %ds", int(time.Since(start).Seconds()))
}

func LogDurationWithPadding(logger log.Logger, start time.Time) {
	LogWithPadding(logger, func() {
		LogDuration(logger, start)
	})
}

func LogWithPadding(logger log.Logger, callback func()) {
	logger.IncreasePadding()
	callback()
	logger.DecreasePadding()
}
