package log

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	log "github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var (
	level      = INFO
	// logger 是应用自己的 logrus 实例。
	// 第三方库（如 metacubex/mihomo）直接使用 logrus 默认 logger，
	// 若共用会导致健康检查/测速时 mihomo 内部噪音（如 vision 握手失败）
	// 以 ERROR 级别刷屏；因此应用使用独立实例，默认 logger 输出丢弃。
	logger     = log.New()
	fileLogger = log.New()
	fileMux    = sync.Mutex{}
)

func init() {
	logger.SetFormatter(&prefixed.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		ForceFormatting: true,
	})
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.InfoLevel)
	fileLogger.SetFormatter(&prefixed.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		DisableColors:   true,
		ForceFormatting: true,
	})
	fileLogger.SetLevel(levelMapping[TRACE])

	// 静默第三方库写入 logrus 默认 logger 的输出（mihomo 内部日志）
	log.SetOutput(io.Discard)
}

func SetLevel(l LogLevel) {
	level = l
	logger.SetLevel(levelMapping[level])
}

func Traceln(format string, v ...interface{}) {
	logger.Traceln(fmt.Sprintf(format, v...))
}

func Debugln(format string, v ...interface{}) {
	logger.Debugln(fmt.Sprintf(format, v...))
}

func Infoln(format string, v ...interface{}) {
	logger.Infoln(fmt.Sprintf(format, v...))
}

func Warnln(format string, v ...interface{}) {
	logger.Warnln(fmt.Sprintf(format, v...))
}

func Errorln(format string, v ...interface{}) {
	logger.Errorln(fmt.Sprintf(format, v...))
}

func Fileln(l LogLevel, data string) {
	if l >= level {
		if f := initFile(filepath.Join(logDir, logFile)); f != nil {
			fileMux.Lock()
			fileLogger.SetOutput(f)
			fileLogger.Logln(levelMapping[l], data)
			fileMux.Unlock()
			_ = f.Close()
		}
	}
}
