package tls

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
)

// Obtain a real, verified TLS 1.3 ticket before exercising the custom client's
// paused resume event. This is not a fabricated SessionState or a timed race.
func uQUICResumeConfig(t *testing.T) *Config {
	t.Helper()
	config := testConfigClient.Clone()
	config.MinVersion = VersionTLS13
	config.NextProtos = []string{"h3"}
	config.SessionTicketsDisabled = false
	config.ClientSessionCache = NewLRUClientSessionCache(2)
	config.OmitEmptyPsk = true
	config.AlwaysIncludePSK = true
	serverConfig := testConfigServer.Clone()
	serverConfig.MinVersion = VersionTLS13
	serverConfig.NextProtos = []string{"h3"}
	serverConfig.SessionTicketsDisabled = false
	client := &testQUICConn{t: t, conn: QUICClient(&QUICConfig{TLSConfig: config, EnableSessionEvents: true})}
	server := &testQUICConn{t: t, conn: QUICServer(&QUICConfig{TLSConfig: serverConfig, EnableSessionEvents: true}), ticketOpts: QUICSessionTicketOptions{EarlyData: true}}
	defer client.conn.Close()
	defer server.conn.Close()
	client.conn.SetTransportParameters(nil)
	server.conn.SetTransportParameters(nil)
	if err := runTestQUICConnection(context.Background(), client, server, nil); err != nil {
		t.Fatal(err)
	}
	if !client.conn.ConnectionState().HandshakeComplete || len(client.conn.ConnectionState().VerifiedChains) == 0 {
		t.Fatal("ticket-seeding connection was not verified")
	}
	if session, ok := config.ClientSessionCache.Get(config.ServerName); !ok || session == nil {
		t.Fatal("ticket-seeding connection did not store a real session")
	}
	return config
}

func newUQUICResumeClient(t *testing.T, config *Config, id ClientHelloID) *UQUICConn {
	t.Helper()
	q := UQUICClient(&QUICConfig{TLSConfig: config, EnableSessionEvents: true}, id)
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

func requireUQUICChannelsClosed(t *testing.T, q *UQUICConn) {
	t.Helper()
	for name, ch := range map[string]chan struct{}{"signalc": q.conn.quic.signalc, "blockedc": q.conn.quic.blockedc} {
		select {
		case _, ok := <-ch:
			if ok {
				t.Errorf("%s remained open", name)
			}
		default:
			t.Errorf("%s was not closed after handshake completion", name)
		}
	}
}

func requireUQUICErrorOnce(t *testing.T, q *UQUICConn) {
	t.Helper()
	first := q.NextEvent()
	if first.Kind != QUICErrorEvent || first.Err == nil {
		t.Fatalf("NextEvent after failure = %+v, want QUICErrorEvent", first)
	}
	var alert AlertError
	if !errors.As(first.Err, &alert) {
		t.Errorf("failure does not preserve a TLS alert: %v", first.Err)
	}
	for range 2 {
		if ev := q.NextEvent(); ev.Kind != QUICNoEvent {
			t.Errorf("event after terminal error = %+v, want QUICNoEvent", ev)
		}
	}
}

func TestUQUICCancelPendingResume(t *testing.T) {
	for _, profile := range []struct {
		name string
		id   ClientHelloID
	}{{"Golang", HelloGolang}, {"Custom", HelloCustom}} {
		for _, mode := range []string{"CloseUndrained", "CloseConsumed", "CancelClose", "CancelDrain"} {
			t.Run(profile.name+"/"+mode, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					config := uQUICResumeConfig(t)
					q := newUQUICResumeClient(t, config, profile.id)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if err := q.Start(ctx); err != nil {
						t.Fatal(err)
					}
					qs := q.conn.quic
					if !qs.waitingForDrain || qs.nextEvent >= len(qs.events) || qs.events[qs.nextEvent].Kind != QUICResumeSession {
						t.Fatal("Start did not pause at a real ResumeSession event")
					}
					if mode == "CloseConsumed" || mode == "CancelDrain" {
						ev := q.NextEvent()
						if ev.Kind != QUICResumeSession || ev.SessionState == nil {
							t.Fatalf("resume event = %+v", ev)
						}
					}
					if mode == "CancelClose" || mode == "CancelDrain" {
						cancel()
					}
					if mode == "CancelDrain" {
						requireUQUICErrorOnce(t, q)
					}
					err := closeUQUICForTest(t, q)
					if !errors.Is(err, AlertError(alertCloseNotify)) {
						t.Errorf("Close error = %v, want close_notify", err)
					}
					if again := closeUQUICForTest(t, q); again != err {
						t.Errorf("repeated Close = %v, want original %v", again, err)
					}
					requireUQUICChannelsClosed(t, q)
					if mode != "CancelDrain" {
						requireUQUICErrorOnce(t, q)
					}
				})
			})
		}
	}
}

func TestUQUICClientHelloBuildError(t *testing.T) {
	for _, profile := range []string{"UnknownPreset", "InvalidGolangALPN"} {
		t.Run(profile, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config := testConfigClient.Clone()
				config.MinVersion = VersionTLS13
				id := ClientHelloID{Client: "unknown-quic-test", Version: "0"}
				if profile == "InvalidGolangALPN" {
					id = HelloGolang
					config.NextProtos = []string{""}
				}
				q := UQUICClient(&QUICConfig{TLSConfig: config}, id)
				q.SetTransportParameters(nil)
				done := make(chan error, 1)
				go func() { done <- q.Start(context.Background()) }()
				synctest.Wait()
				select {
				case err := <-done:
					if err == nil {
						t.Error("Start unexpectedly succeeded with an invalid ClientHello")
					}
				default:
					// The historical early-return bug left Start blocked after
					// its handshake goroutine exited. Release that waiter so the
					// regression fails without leaking a goroutine in the bubble.
					t.Error("Start stranded after ClientHello construction failed")
					close(q.conn.quic.blockedc)
					close(q.conn.quic.signalc)
					<-done
				}
				requireUQUICChannelsClosed(t, q)
				requireUQUICErrorOnce(t, q)
				if err := closeUQUICForTest(t, q); err == nil {
					t.Error("Close lost the original construction error")
				}
			})
		})
	}
}
