package eavesarp_ng

import (
	"context"
)

type (
	SenderTypeConst interface {
		SendArpCfg | DoDnsCfg
	}
	SenderFunc[T SenderTypeConst] func(Cfg, T) error
)

// SenderServer is used to send ARP and DNS traffic. It starts a
// background routine that listens for arguments over a channel,
// which are then passed to the sender function. The server terminates
// upon cancellation of the context.
//
// A Sleeper is invoked during each after each execution of sender to
// avoid degrading network conditions.
func SenderServer[T SenderTypeConst](ctx context.Context, cfg Cfg, sleeper Sleeper, ch chan T, sender SenderFunc[T]) error {
	errCh := make(chan error) // used by sender loop routine to indicate an error

	// start a perpetual sender loop
	go func() {
		for {
			sleeper.Sleep()
			select {
			case <-ctx.Done():
				return
			case v := <-ch:
				// call the sender
				if err := sender(cfg, v); err != nil {
					errCh <- err
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		// return an error
		return err
	}
}
