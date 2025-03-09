package eavesarp_ng

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net"
)

type (
	Cfg struct {
		db             *sql.DB
		ipNet          *net.IPNet
		iface          *net.Interface
		log            *zap.Logger
		zap            *zap.Config
		arpSenderC     chan SendArpCfg
		activeArps     *LockMap[ActiveArp]
		dnsSenderC     chan DoDnsCfg
		activeDns      *LockMap[DoDnsCfg]
		dnsFailCounter *FailCounter
	}
)

// NewLogger instantiates a Zap logger for the eavesarp_ng module.
//
// level is one of:
//
// - debug
// - info
// - warn
// - error
// - dpanic
// - panic
// - fatal
//
// outputPaths and errOutputPaths is file paths or URLs to write logs
// to. Setting outputPaths to nil configures the logger to send non-error
// records to stdout, and setting errOutputPaths to nil configures the
// logger to send error records to stderr.
func NewLogger(level string, outputPaths, errOutputPaths []string) (*zap.Logger, error) {

	if outputPaths == nil {
		outputPaths = []string{"stdout"}
	}
	if errOutputPaths == nil {
		errOutputPaths = []string{"stderr"}
	}

	lvl, err := zap.ParseAtomicLevel(level)
	if err != nil {
		return nil, fmt.Errorf("error parsing log level: %v", err)
	}

	zapCfg := zap.Config{
		Level:             lvl,
		Development:       false,
		DisableCaller:     false,
		DisableStacktrace: false,
		Sampling:          nil,
		Encoding:          "json",
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:  "message",
			LevelKey:    "level",
			TimeKey:     "time",
			EncodeLevel: zapcore.LowercaseLevelEncoder,
			EncodeTime:  zapcore.ISO8601TimeEncoder,
		},
		OutputPaths:      outputPaths,
		ErrorOutputPaths: errOutputPaths,
	}

	return zapCfg.Build()
}

// NewCfg creates a Cfg for various eavesarp_ng functions.
//
// dsn is the Data Source Name describing where to find the SQLite database. The
// database is initialized along with Cfg.
//
// ifaceName and ifaceAddr describe the network interface to monitor,
// the latter of which can be empty (""), indicating that the first non-loopback
// address should be used.
//
// log enables logging. See NewLogger.
func NewCfg(dsn string, ifaceName, ifaceAddr string, log *zap.Logger) (cfg Cfg, err error) {
	if log == nil {
		err = errors.New("nil logger")
		return
	}
	cfg.log = log
	if err = cfg.getInterface(ifaceName, ifaceAddr); err != nil {
		return
	}
	cfg.dnsSenderC = make(chan DoDnsCfg, 50)
	cfg.activeDns = NewLockMap(make(map[string]*DoDnsCfg))
	cfg.arpSenderC = make(chan SendArpCfg, 50)
	cfg.activeArps = NewLockMap(make(map[string]*ActiveArp))
	cfg.db, err = cfg.initDb(dsn)
	cfg.dnsFailCounter = NewFailCounter(DnsMaxFailures)
	return
}

// DB returns the database connection initialized by NewCfg.
func (cfg *Cfg) DB() *sql.DB {
	return cfg.db
}

func (cfg *Cfg) Shutdown() {
	if cfg.db != nil {
		cfg.db.Close()
	}
	close(cfg.arpSenderC)
	close(cfg.dnsSenderC)
}

func (cfg *Cfg) initDb(dsn string) (db *sql.DB, err error) {
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		cfg.log.Error("error opening db", zap.Error(err))
		return
	}
	db.SetMaxOpenConns(1)
	// TODO test the connection by pinging the database
	_, err = db.ExecContext(context.Background(), SchemaSql)
	if err != nil {
		cfg.log.Error("error while applying database schema", zap.Error(err))
		return
	}
	return
}

// getInterface gets the network interface described by name and addr.
//
// addr is optional (can be empty) and is used to specify which address
// to listen for when multiple IPv4 addresses are assigned to the interface.
func (cfg *Cfg) getInterface(name string, addr string) (err error) {

	var iAddr net.IP
	if addr != "" {
		if iAddr = net.ParseIP(addr); iAddr == nil {
			err = errors.New("invalid addr")
			return
		}
	}

	cfg.iface, err = net.InterfaceByName(name)
	if err != nil {
		cfg.log.Error("error looking up network interface", zap.Error(err))
		return
	}

	var addrs []net.Addr
	addrs, err = cfg.iface.Addrs()
	if err != nil {
		cfg.log.Error("failed to obtain ip address from network interface", zap.Error(err))
		return
	} else {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() {
				if ip4 := n.IP.To4(); ip4 != nil {
					if addr != "" && ip4.String() != addr {
						continue
					}
					cfg.ipNet = &net.IPNet{
						IP:   ip4,
						Mask: n.Mask[len(n.Mask)-4:],
					}
				}
			}
		}
	}

	if cfg.ipNet == nil {
		cfg.log.Warn("failed to find network interface", zap.String("ifaceName", name))
		if addr != "" {
			err = fmt.Errorf("failed to find ip (%v) bound to interface (%v)", addr, name)
			cfg.log.Error("error looking up network interface", zap.Error(err))
		}
	}

	return
}
