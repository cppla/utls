package tls

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
)

// closeUQUICForTest also releases the old Close implementation if it fails to
// wake the handshake. That makes the regression fail without stranding either
// goroutine or relying on a wall-clock timeout.
func closeUQUICForTest(t *testing.T, q *UQUICConn) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- q.Close() }()
	synctest.Wait()
	select {
	case err := <-done:
		return err
	default:
		t.Error("Close did not wake the blocked QUIC handshake")
		<-q.conn.quic.signalc
		synctest.Wait()
		return <-done
	}
}

func newUQUICCloseClient(t *testing.T, id ClientHelloID) *UQUICConn {
	t.Helper()
	config := testConfigClient.Clone()
	config.MinVersion = VersionTLS13
	config.NextProtos = []string{"h3"}
	config.SessionTicketsDisabled = true
	q := UQUICClient(&QUICConfig{TLSConfig: config}, id)
	if id == HelloCustom {
		spec, err := UTLSIdToSpec(HelloChrome_155)
		if err != nil {
			t.Fatal(err)
		}
		for _, ext := range spec.Extensions {
			switch ext := ext.(type) {
			case *ALPNExtension:
				ext.AlpnProtocols = []string{"h3"}
			case *SupportedVersionsExtension:
				ext.Versions = []uint16{GREASE_PLACEHOLDER, VersionTLS13}
			}
		}
		spec.Extensions = append(spec.Extensions, &QUICTransportParametersExtension{})
		if err := q.ApplyPreset(&spec); err != nil {
			t.Fatal(err)
		}
	}
	q.SetTransportParameters(nil)
	return q
}

func TestUQUICClose(t *testing.T) {
	for _, profile := range []struct {
		name string
		id   ClientHelloID
	}{{"Golang", HelloGolang}, {"Custom", HelloCustom}} {
		t.Run(profile.name, func(t *testing.T) {
			t.Run("BeforeStart", func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					q := newUQUICCloseClient(t, profile.id)
					for range 2 {
						if err := closeUQUICForTest(t, q); err != nil {
							t.Errorf("Close before Start: %v", err)
						}
					}
				})
			})
			for _, canceled := range []bool{false, true} {
				name := "Blocked"
				if canceled {
					name = "CanceledWhileBlocked"
				}
				t.Run(name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						q := newUQUICCloseClient(t, profile.id)
						ctx, cancel := context.WithCancel(context.Background())
						defer cancel()
						if err := q.Start(ctx); err != nil {
							t.Fatal(err)
						}
						if canceled {
							cancel()
						}
						first := closeUQUICForTest(t, q)
						if !errors.Is(first, AlertError(alertCloseNotify)) {
							t.Errorf("Close error = %v, want close_notify", first)
						}
						if second := closeUQUICForTest(t, q); second != first {
							t.Errorf("repeated Close = %v, want original error %v", second, first)
						}
						for _, ch := range []chan struct{}{q.conn.quic.signalc, q.conn.quic.blockedc} {
							if _, ok := <-ch; ok {
								t.Error("handshake channel is not closed after Close")
							}
						}
					})
				})
			}
			t.Run("Completed", func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					client := newUQUICCloseClient(t, profile.id)
					defer closeUQUICForTest(t, client)
					config := testConfigServer.Clone()
					config.MinVersion = VersionTLS13
					config.NextProtos = []string{"h3"}
					config.SessionTicketsDisabled = true
					server := QUICServer(&QUICConfig{TLSConfig: config})
					defer server.Close()
					server.SetTransportParameters(nil)
					completeUQUICCloseHandshake(t, client, server)
					if len(client.ConnectionState().VerifiedChains) == 0 {
						t.Fatal("handshake did not verify the server certificate")
					}
					for range 2 {
						if err := closeUQUICForTest(t, client); err != nil {
							t.Errorf("Close after completed handshake: %v", err)
						}
					}
				})
			})
		})
	}
}

// Exchange real QUIC-TLS events in memory; no network or packet transport is
// needed to reach a verified, completed handshake.
func completeUQUICCloseHandshake(t *testing.T, client *UQUICConn, server *QUICConn) {
	t.Helper()
	type endpoint interface {
		Start(context.Context) error
		NextEvent() QUICEvent
		HandleData(QUICEncryptionLevel, []byte) error
		ConnectionState() ConnectionState
	}
	peers := [2]endpoint{client, server}
	for _, peer := range peers {
		if err := peer.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for step, idle := 0, 0; step < 100; step++ {
		e := peers[0].NextEvent()
		switch e.Kind {
		case QUICNoEvent:
			idle++
			peers[0], peers[1] = peers[1], peers[0]
			if idle == 2 {
				for _, peer := range peers {
					if !peer.ConnectionState().HandshakeComplete {
						t.Fatal("QUIC handshake stalled before completion")
					}
				}
				return
			}
		case QUICWriteData:
			if err := peers[1].HandleData(e.Level, e.Data); err != nil {
				t.Fatal(err)
			}
		case QUICErrorEvent:
			t.Fatalf("QUIC handshake error: %v", e.Err)
		case QUICTransportParametersRequired:
			t.Fatal("transport parameters unexpectedly missing")
		}
		if e.Kind != QUICNoEvent {
			idle = 0
		}
	}
	t.Fatal("too many QUIC handshake events")
}
