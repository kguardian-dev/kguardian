package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

var Log *logrus.Logger

// Init initializes the global logger with the specified log level
func Init(level string) {
	Log = logrus.New()

	// Set output to stdout
	Log.SetOutput(os.Stdout)

	// Use JSON formatter for structured logging
	Log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})

	// Set log level
	Log.SetLevel(parseLogLevel(level))
}

// parseLogLevel converts a string log level to logrus.Level
func parseLogLevel(level string) logrus.Level {
	switch level {
	case "debug", "DEBUG":
		return logrus.DebugLevel
	case "info", "INFO":
		return logrus.InfoLevel
	case "warn", "WARN", "warning", "WARNING":
		return logrus.WarnLevel
	case "error", "ERROR":
		return logrus.ErrorLevel
	default:
		return logrus.InfoLevel
	}
}

// WithField creates a new logger entry with an additional field
func WithField(key string, value interface{}) *logrus.Entry {
	return Log.WithField(key, value)
}

// WithFields creates a new logger entry with multiple additional fields
func WithFields(fields logrus.Fields) *logrus.Entry {
	return Log.WithFields(fields)
}
