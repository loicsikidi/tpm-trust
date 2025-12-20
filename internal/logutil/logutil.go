package logutil

import (
	"time"

	"github.com/caarlos0/log"
)

func LogDuration(logger *log.Logger, start time.Time) {
	logger.IncreasePadding()
	logger.Infof("took: %ds", int(time.Since(start).Seconds()))
	logger.ResetPadding()
}
