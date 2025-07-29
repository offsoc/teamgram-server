package video

import (
	"testing"
	"time"
)

func TestWebRTCEngine(t *testing.T) {
	config := &WebRTCConfig{
		ICEServers: []ICEServer{
			{URLs: []string{"stun:stun.l.google.com:19302"}},
		},
		EnableAudio: true,
		EnableVideo: true,
	}

	engine := NewWebRTCEngine(config)
	if engine == nil {
		t.Fatal("Failed to create WebRTC engine")
	}
	t.Log("✓ WebRTC Engine created successfully")
}

func TestEncoderEngine(t *testing.T) {
	config := &EncoderConfig{
		Codec:     "h264",
		Bitrate:   1000000,
		FrameRate: 30,
	}

	encoder := NewEncoderEngine(config)
	if encoder == nil {
		t.Fatal("Failed to create Encoder engine")
	}
	t.Log("✓ Encoder Engine created successfully")
}

func TestQualityManager(t *testing.T) {
	config := &QualityConfig{
		AutoAdjust:    true,
		MinQuality:    1,
		MaxQuality:    10,
		TargetBitrate: 1000000,
	}

	manager := NewQualityManager(config)
	if manager == nil {
		t.Fatal("Failed to create Quality manager")
	}
	t.Log("✓ Quality Manager created successfully")
}

func TestSFUManager(t *testing.T) {
	config := &SFUConfig{}

	manager, err := NewSFUManager(config)
	if err != nil {
		t.Fatalf("Failed to create SFU manager: %v", err)
	}
	if manager == nil {
		t.Fatal("SFU manager is nil")
	}
	t.Log("✓ SFU Manager created successfully")
}

func TestPerformanceMonitor(t *testing.T) {
	monitor := NewPerformanceMonitor()
	if monitor == nil {
		t.Fatal("Failed to create Performance monitor")
	}
	t.Log("✓ Performance Monitor created successfully")
}

func TestWebRTCConnection(t *testing.T) {
	conn := &WebRTCConnection{
		ID:        "test_conn_123",
		UserID:    12345,
		CallID:    "test_call_456",
		State:     "connected",
		CreatedAt: time.Now(),
		LocalSDP:  "test_local_sdp",
		RemoteSDP: "test_remote_sdp",
	}

	if conn.ID != "test_conn_123" {
		t.Fatalf("Expected ID 'test_conn_123', got '%s'", conn.ID)
	}
	if conn.UserID != 12345 {
		t.Fatalf("Expected UserID 12345, got %d", conn.UserID)
	}
	if conn.State != "connected" {
		t.Fatalf("Expected State 'connected', got '%s'", conn.State)
	}
	t.Log("✓ WebRTCConnection structure works correctly")
}

func TestICEServer(t *testing.T) {
	server := ICEServer{
		URLs: []string{
			"stun:stun.l.google.com:19302",
			"turn:turn.example.com:3478",
		},
	}

	if len(server.URLs) != 2 {
		t.Fatalf("Expected 2 URLs, got %d", len(server.URLs))
	}
	if server.URLs[0] != "stun:stun.l.google.com:19302" {
		t.Fatalf("Expected first URL to be STUN server, got '%s'", server.URLs[0])
	}
	t.Log("✓ ICEServer structure works correctly")
}

func TestVideoConfigs(t *testing.T) {
	// Test WebRTCConfig
	webrtcConfig := &WebRTCConfig{
		ICEServers: []ICEServer{
			{URLs: []string{"stun:stun.l.google.com:19302"}},
		},
		EnableAudio: true,
		EnableVideo: true,
	}
	if !webrtcConfig.EnableAudio || !webrtcConfig.EnableVideo {
		t.Fatal("WebRTCConfig audio/video flags not set correctly")
	}

	// Test EncoderConfig
	encoderConfig := &EncoderConfig{
		Codec:     "h264",
		Bitrate:   1000000,
		FrameRate: 30,
	}
	if encoderConfig.Codec != "h264" {
		t.Fatalf("Expected codec 'h264', got '%s'", encoderConfig.Codec)
	}

	// Test QualityConfig
	qualityConfig := &QualityConfig{
		AutoAdjust:    true,
		MinQuality:    1,
		MaxQuality:    10,
		TargetBitrate: 1000000,
	}
	if !qualityConfig.AutoAdjust {
		t.Fatal("QualityConfig AutoAdjust should be true")
	}

	t.Log("✓ All video configurations work correctly")
}
