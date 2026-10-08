package tls

import (
	"bytes"
	"context"
	"io"
	"testing"
	"testing/synctest"
)

func newUQUICParametersClient(id ClientHelloID) *UQUICConn {
	config := testConfigClient.Clone()
	config.MinVersion = VersionTLS13
	config.NextProtos = []string{"h3"}
	config.SessionTicketsDisabled = true
	return UQUICClient(&QUICConfig{TLSConfig: config}, id)
}

func uQUICParametersSpec(ext *QUICTransportParametersExtension) *ClientHelloSpec {
	return &ClientHelloSpec{
		CipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
			&SupportedCurvesExtension{Curves: []CurveID{X25519}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ECDSAWithP256AndSHA256}},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
			&ALPNExtension{AlpnProtocols: []string{"h3"}},
			ext,
		},
	}
}

func uQUICActiveParameters(t *testing.T, q *UQUICConn) *QUICTransportParametersExtension {
	t.Helper()
	for _, ext := range q.conn.Extensions {
		if ext, ok := ext.(*QUICTransportParametersExtension); ok {
			return ext
		}
	}
	t.Fatal("active preset has no transport parameters extension")
	return nil
}

func uQUICEncodedParameters(t *testing.T, ext *QUICTransportParametersExtension) []byte {
	t.Helper()
	wire := make([]byte, ext.Len())
	if n, err := ext.Read(wire); n != len(wire) || err != io.EOF {
		t.Fatalf("extension Read = (%d, %v), want (%d, EOF)", n, err, len(wire))
	}
	return wire[4:]
}

// Deliberately use a non-numeric parameter order, a GREASE parameter, and
// non-minimal varints for initial_source_connection_id's ID and length.
// A parser/re-serializer must not replace the caller's wire encoding.
func uQUICRawParameters(sourceCID []byte) []byte {
	params := []byte{0x1b, 0x02, 0xca, 0xfe, 0x40, 0x0f, 0x40, byte(len(sourceCID))}
	params = append(params, sourceCID...)
	return append(params, 0x04, 0x02, 0x44, 0x00)
}

func TestUQUICSetTransportParametersOwnership(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params []byte
	}{
		{"Nil", nil},
		{"Empty", []byte{}},
		{"Raw", uQUICRawParameters([]byte{0x01, 0x02, 0x03, 0x04})},
	} {
		for _, beforePreset := range []bool{false, true} {
			order := "AfterPreset"
			if beforePreset {
				order = "BeforePreset"
			}
			t.Run(tc.name+"/"+order, func(t *testing.T) {
				q := newUQUICParametersClient(HelloCustom)
				original := &QUICTransportParametersExtension{
					TransportParameters: TransportParameters{InitialSourceConnectionID{0x77, 0x88}},
				}
				// Populate the cache before ApplyPreset clones it.
				originalWire := uQUICEncodedParameters(t, original)
				spec := uQUICParametersSpec(original)
				params := bytes.Clone(tc.params)
				if beforePreset {
					q.SetTransportParameters(params)
				}
				if err := q.ApplyPreset(spec); err != nil {
					t.Fatal(err)
				}
				active := uQUICActiveParameters(t, q)
				if active == original {
					t.Fatal("ApplyPreset did not clone the extension")
				}
				if !beforePreset {
					q.SetTransportParameters(params)
				}
				if len(params) > 0 {
					params[0] ^= 0xff
				}
				for name, got := range map[string][]byte{
					"stored": q.conn.quic.transportParams,
					"active": active.marshalResult,
					"wire":   uQUICEncodedParameters(t, active),
				} {
					if got == nil || !bytes.Equal(got, tc.params) {
						t.Errorf("%s parameters = %x (nil=%v), want %x and non-nil", name, got, got == nil, tc.params)
					}
				}
				if !bytes.Equal(uQUICEncodedParameters(t, original), originalWire) {
					t.Error("setter mutated the caller's cached preset")
				}
				if got := original.TransportParameters[0].Value(); !bytes.Equal(got, []byte{0x77, 0x88}) {
					t.Error("setter mutated the caller's structured parameters")
				}
				// A later setter must replace a filled cache, and reapplying a
				// preset must not silently replace explicitly provided bytes.
				replacement := uQUICRawParameters(nil)
				q.SetTransportParameters(replacement)
				if err := q.ApplyPreset(spec); err != nil {
					t.Fatal(err)
				}
				if got := uQUICEncodedParameters(t, uQUICActiveParameters(t, q)); !bytes.Equal(got, replacement) {
					t.Errorf("reapplied preset parameters = %x, want %x", got, replacement)
				}
				// Reusing the same caller-owned preset for a second connection
				// must not inherit the first connection's source CID or setter.
				other := newUQUICParametersClient(HelloCustom)
				if err := other.ApplyPreset(spec); err != nil {
					t.Fatal(err)
				}
				if other.conn.quic.transportParams != nil {
					t.Error("applying a preset marked transport parameters explicitly set")
				}
				if got := uQUICEncodedParameters(t, uQUICActiveParameters(t, other)); !bytes.Equal(got, originalWire) {
					t.Errorf("unset connection parameters = %x, want preset %x", got, originalWire)
				}
			})
		}
	}
}

func TestUQUICSetTransportParametersHandshake(t *testing.T) {
	for _, tc := range []struct {
		name         string
		id           ClientHelloID
		params       []byte
		beforePreset bool
		delayed      bool
	}{
		{"CustomNil", HelloCustom, nil, false, false},
		{"CustomEmpty", HelloCustom, []byte{}, true, false},
		{"CustomEmptySourceCID", HelloCustom, uQUICRawParameters(nil), false, false},
		{"CustomSourceCID", HelloCustom, uQUICRawParameters([]byte{1, 2, 3, 4}), false, false},
		{"CustomSetterBeforePreset", HelloCustom, uQUICRawParameters([]byte{5, 6, 7, 8}), true, false},
		{"Golang", HelloGolang, uQUICRawParameters([]byte{9, 10, 11, 12}), false, false},
		{"GolangDelayed", HelloGolang, uQUICRawParameters([]byte{13, 14, 15, 16}), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := newUQUICParametersClient(tc.id)
				defer client.Close()
				params := bytes.Clone(tc.params)
				if tc.beforePreset {
					client.SetTransportParameters(params)
				}
				if tc.id == HelloCustom {
					ext := &QUICTransportParametersExtension{
						TransportParameters: TransportParameters{InitialSourceConnectionID{0xff}},
					}
					_ = uQUICEncodedParameters(t, ext)
					if err := client.ApplyPreset(uQUICParametersSpec(ext)); err != nil {
						t.Fatal(err)
					}
					// Model a caller retaining and modifying its original spec:
					// the active extension must remain connection-owned.
					ext.TransportParameters = TransportParameters{InitialSourceConnectionID{0xee}}
					ext.marshalResult = nil
				}
				if !tc.beforePreset && !tc.delayed {
					client.SetTransportParameters(params)
				}
				if !tc.delayed && len(params) > 0 {
					params[0] ^= 0xff
				}
				serverConfig := testConfigServer.Clone()
				serverConfig.MinVersion = VersionTLS13
				serverConfig.NextProtos = []string{"h3"}
				serverConfig.SessionTicketsDisabled = true
				server := QUICServer(&QUICConfig{TLSConfig: serverConfig})
				defer server.Close()
				server.SetTransportParameters(nil)
				runUQUICParametersHandshake(t, client, server, tc.params, tc.delayed)
			})
		})
	}
}

func runUQUICParametersHandshake(t *testing.T, client *UQUICConn, server *QUICConn, want []byte, delayed bool) {
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
	gotParameters, gotRequired := false, false
	for step, src, idle := 0, 0, 0; step < 100; step++ {
		e := peers[src].NextEvent()
		switch e.Kind {
		case QUICNoEvent:
			idle++
			src = 1 - src
			if idle == 2 {
				for _, peer := range peers {
					state := peer.ConnectionState()
					if !state.HandshakeComplete || state.Version != VersionTLS13 || state.NegotiatedProtocol != "h3" || state.DidResume {
						t.Fatal("expected a completed, non-resumed TLS 1.3 h3 handshake")
					}
				}
				if len(client.ConnectionState().VerifiedChains) == 0 {
					t.Error("server certificate was not verified")
				}
				if !gotParameters || gotRequired != delayed {
					t.Errorf("parameters received=%v, required=%v; want true, %v", gotParameters, gotRequired, delayed)
				}
				return
			}
		case QUICWriteData:
			if err := peers[1-src].HandleData(e.Level, e.Data); err != nil {
				t.Fatal(err)
			}
		case QUICTransportParameters:
			if src == 1 {
				if gotParameters || !bytes.Equal(e.Data, want) {
					t.Fatalf("peer received parameters %x, want exact wire bytes %x once", e.Data, want)
				}
				gotParameters = true
			}
		case QUICTransportParametersRequired:
			if src != 0 || !delayed || gotRequired {
				t.Fatal("unexpected transport parameters request")
			}
			gotRequired = true
			params := bytes.Clone(want)
			client.SetTransportParameters(params)
			if len(params) > 0 {
				params[0] ^= 0xff
			}
		case QUICSetReadSecret, QUICSetWriteSecret:
			if e.Level == QUICEncryptionLevelEarly {
				t.Fatal("unexpected 0-RTT secret")
			}
		case QUICErrorEvent:
			t.Fatalf("QUIC handshake error: %v", e.Err)
		}
		if e.Kind != QUICNoEvent {
			idle = 0
		}
	}
	t.Fatal("too many QUIC handshake events")
}
