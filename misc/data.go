package misc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// VictimDataSender indicates that the Data was sent
	// by the victim side of a conversation.
	VictimDataSender DataSender = "victim"
	// DownstreamDataSender indicates that the Data was sent
	// by the victim side of a conversation.
	DownstreamDataSender DataSender = "downstream"
)

type (
	// DataSender indicates the address that sent Data.
	DataSender string

	// Data is extracted from poisoned traffic for logging.
	Data struct {
		// Time when the Raw was logged.
		Time time.Time `json:"time"`
		// Sender of the Raw indicates which side of the conversation
		// sent the Raw.
		//
		// See VictimDataSender and DownstreamDataSender.
		Sender DataSender `json:"sender"`
		// VictimAddr is the address of the victim side of the
		// conversation.
		VictimAddr Addr `json:"victim_address"`
		// ProxyAddr is the address of the proxy used to forward
		// traffic to DownstreamAddr during the conversation.
		ProxyAddr Addr `json:"proxy_address"`
		// DownstreamAddr is the address that receives Raw
		// from the VictimAddr via ProxyAddr.
		DownstreamAddr *Addr `json:"downstream_address,omitempty"`
		// Transport protocol used to send the Raw.
		Transport Transport `json:"transport"`
		// Data is the base64 encoded value of Raw.
		Data string `json:"data"`
		Raw  []byte `json:"-"`
	}
)

// Log JSON marshals the Data to log.
//
// If Time is nil, the current time is set to the log record
// before writing it.
//
// If Data is empty (""), Raw is base64 encoded and set to
// Data before writing.
func (d *Data) Log(w io.Writer) (err error) {
	if w == nil {
		err = errors.New("nil log")
		return
	}
	if d.Time.IsZero() {
		d.Time = time.Now()
	}
	if d.Data == "" {
		d.Data = base64.StdEncoding.EncodeToString(d.Raw)
	}
	var b []byte
	if b, err = json.Marshal(d); err != nil {
		err = fmt.Errorf("failed to json marshal data: %w", err)
	}
	b = append(b, '\n')
	if _, err = w.Write(b); err != nil {
		err = fmt.Errorf("failed to write data to log: %w", err)
	}
	return
}
