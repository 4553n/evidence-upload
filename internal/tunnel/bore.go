package tunnel

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Native implementation of the bore tunnel protocol
// (https://github.com/ekzhang/bore). Messages are null-delimited JSON frames of
// at most 256 bytes over TCP; per-connection data streams are raw pipes after
// an Accept handshake. The client runs in-process: nothing is downloaded,
// dropped to disk, or executed at runtime — the application stays a single
// binary, which also avoids antivirus dropper heuristics.
//
// Wire format (serde external tagging, JSON, NUL-terminated):
//
//	client -> server  {"Hello":0}          request random public port
//	server -> client  {"Hello":41739}      public port assigned
//	server -> client  {"Connection":"<uuid>"}   visitor arrived
//	client -> server  {"Accept":"<uuid>"}  on a NEW connection, then raw bytes
//	server -> client  "Heartbeat"          unit variant, bare JSON string
//	server -> client  {"Error":"..."}      fatal
//	server -> client  {"Challenge":"<uuid>"}    auth required (unsupported)
const (
	boreHost        = "bore.pub"
	boreControlAddr = "bore.pub:7835"
	boreMaxFrame    = 256
	boreDialTimeout = 3 * time.Second
)

type BoreTunnel struct {
	mu         sync.Mutex
	conn       net.Conn
	localPort  int
	publicPort uint16
	publicURL  string
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

func NewBoreTunnel() *BoreTunnel {
	return &BoreTunnel{stopCh: make(chan struct{})}
}

// Start opens the control connection and requests a random public port.
// Returns the public URL (http scheme — pair with TLS for encryption).
func (b *BoreTunnel) Start(localPort int) (string, error) {
	conn, err := net.DialTimeout("tcp", boreControlAddr, boreDialTimeout)
	if err != nil {
		return "", fmt.Errorf("connect to %s: %w", boreControlAddr, err)
	}

	conn.SetDeadline(time.Now().Add(boreDialTimeout))
	defer conn.SetDeadline(time.Time{})

	if err := writeFrame(conn, map[string]any{"Hello": 0}); err != nil {
		conn.Close()
		return "", fmt.Errorf("send hello: %w", err)
	}
	frame, err := readFrame(conn)
	if err != nil {
		conn.Close()
		return "", fmt.Errorf("read hello: %w", err)
	}
	msg, err := parseServerMessage(frame)
	if err != nil {
		conn.Close()
		return "", err
	}
	switch msg.Kind {
	case "Hello":
		// ok
	case "Challenge":
		conn.Close()
		return "", fmt.Errorf("bore server requires authentication, which is not supported")
	case "Error":
		conn.Close()
		return "", fmt.Errorf("bore server error: %s", msg.Text)
	default:
		conn.Close()
		return "", fmt.Errorf("unexpected initial message %q", msg.Kind)
	}

	b.mu.Lock()
	b.conn = conn
	b.localPort = localPort
	b.publicPort = msg.Port
	b.publicURL = fmt.Sprintf("http://%s:%d", boreHost, msg.Port)
	b.mu.Unlock()

	fmt.Printf("Tunnel established: %s:%d -> localhost:%d\n", boreHost, msg.Port, localPort)

	b.wg.Add(1)
	go b.listen()
	return b.publicURL, nil
}

// listen dispatches incoming visitor connections from the control stream.
func (b *BoreTunnel) listen() {
	defer b.wg.Done()
	for {
		frame, err := readFrame(b.conn)
		if err != nil {
			select {
			case <-b.stopCh:
			default:
				fmt.Printf("Tunnel connection closed: %v\n", err)
			}
			return
		}
		msg, err := parseServerMessage(frame)
		if err != nil {
			continue
		}
		switch msg.Kind {
		case "Connection":
			b.wg.Add(1)
			go func(id string) {
				defer b.wg.Done()
				b.handleConnection(id)
			}(msg.ID)
		case "Error":
			fmt.Printf("Tunnel server error: %s\n", msg.Text)
		case "Heartbeat", "Hello", "Challenge":
			// ignored, matching the reference client
		}
	}
}

// handleConnection proxies one visitor: open a fresh server stream, accept the
// connection by UUID, then pipe raw bytes between the visitor and the local port.
func (b *BoreTunnel) handleConnection(id string) {
	remote, err := net.DialTimeout("tcp", boreControlAddr, boreDialTimeout)
	if err != nil {
		fmt.Printf("Tunnel: failed to open data stream: %v\n", err)
		return
	}
	defer remote.Close()

	if err := writeFrame(remote, map[string]any{"Accept": id}); err != nil {
		return
	}

	local, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", b.localPort), boreDialTimeout)
	if err != nil {
		fmt.Printf("Tunnel: failed to reach local port %d: %v\n", b.localPort, err)
		return
	}
	defer local.Close()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(remote, local)
		closeWrite(remote)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(local, remote)
		closeWrite(local)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// Stop closes the control connection and waits for connection handlers.
func (b *BoreTunnel) Stop() {
	close(b.stopCh)
	b.mu.Lock()
	if b.conn != nil {
		b.conn.Close()
	}
	b.mu.Unlock()
	b.wg.Wait()
}

func (b *BoreTunnel) PublicURL() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.publicURL
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}

// serverMessage is a decoded ServerMessage frame.
type serverMessage struct {
	Kind string // Hello | Connection | Challenge | Heartbeat | Error
	Port uint16 // Hello
	ID   string // Connection / Challenge
	Text string // Error
}

func parseServerMessage(frame []byte) (serverMessage, error) {
	// Unit variants serialize as a bare JSON string ("Heartbeat").
	var unit string
	if err := json.Unmarshal(frame, &unit); err == nil {
		return serverMessage{Kind: unit}, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(frame, &obj); err != nil {
		return serverMessage{}, fmt.Errorf("invalid frame %q", frame)
	}
	for kind, raw := range obj {
		switch kind {
		case "Hello":
			var p uint16
			if err := json.Unmarshal(raw, &p); err != nil {
				return serverMessage{}, fmt.Errorf("invalid hello %q", frame)
			}
			return serverMessage{Kind: "Hello", Port: p}, nil
		case "Connection", "Challenge":
			var id string
			if err := json.Unmarshal(raw, &id); err != nil {
				return serverMessage{}, fmt.Errorf("invalid %s %q", kind, frame)
			}
			return serverMessage{Kind: kind, ID: id}, nil
		case "Error":
			var t string
			json.Unmarshal(raw, &t)
			return serverMessage{Kind: "Error", Text: t}, nil
		}
	}
	return serverMessage{}, fmt.Errorf("unknown message %q", frame)
}

// readFrame reads one NUL-terminated frame. It reads byte by byte so that no
// payload bytes beyond the terminator are consumed — critical on Accept
// streams, where proxied bytes follow the handshake immediately.
func readFrame(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, 32)
	var b [1]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return nil, err
		}
		if b[0] == 0 {
			return buf, nil
		}
		buf = append(buf, b[0])
		if len(buf) > boreMaxFrame {
			return nil, fmt.Errorf("frame exceeds %d bytes", boreMaxFrame)
		}
	}
}

func writeFrame(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data)+1 > boreMaxFrame {
		return fmt.Errorf("frame exceeds %d bytes", boreMaxFrame)
	}
	_, err = w.Write(append(data, 0))
	return err
}
