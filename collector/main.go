package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"errors"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	ciliumEbpf "github.com/cilium/ebpf"
	"github.com/copsec/collector/internal/bpf"
	"github.com/copsec/collector/internal/cluster"
	"github.com/copsec/collector/internal/dpi"
	"github.com/copsec/collector/internal/management"
	"github.com/copsec/collector/internal/network"
	"github.com/copsec/collector/pkg/bgp"
	"github.com/copsec/collector/pkg/dns"
	"github.com/copsec/collector/pkg/ebpf"
	"github.com/copsec/collector/pkg/healing"
	"github.com/copsec/collector/pkg/honeypot"
	"github.com/copsec/collector/pkg/tarpit"
	"github.com/copsec/collector/pkg/ttp"
	"github.com/copsec/collector/pkg/yara"
	copsecproto "github.com/copsec/collector/proto"
)

func main() {
	controllerAddr := flag.String("controller", "127.0.0.1:50051", "Controller gRPC host:port address (over Tailscale / LAN)")
	nodeIdentityPath := flag.String("node-identity", "/etc/copsec/node.json", "Path to node identity file")
	bufferDbPath := flag.String("buffer-db", "/var/lib/copsec/buffer.db", "Path to offline SQLite / buffer queue database")
	nginxLogPath := flag.String("nginx-log", "/var/log/nginx/access.log", "Path to Nginx access log file")
	authLogPath := flag.String("auth-log", "/var/log/auth.log", "Path to SSH / Auth log file")
	syslogPath := flag.String("syslog", "/var/log/syslog", "Path to system syslog file")
	suricataLogPath := flag.String("suricata-log", "/var/log/suricata/eve.json", "Path to Suricata EVE JSON log file")
	snortLogPath := flag.String("snort-log", "/var/log/snort/alert_json.txt", "Path to Snort 3 Alert JSON log file")
	auditLogPath := flag.String("audit-log", "/var/log/audit/audit.log", "Path to Linux auditd log file")
	offsetFilePath := flag.String("offset-file", "/var/lib/copsec/offsets.json", "Path to save/load file offsets")
	whitelistPath := flag.String("whitelist", "/etc/copsec/whitelist.json", "Path to whitelist configuration JSON")
	whitelistYamlPath := flag.String("whitelist-yaml", "/etc/copsec/whitelist.yaml", "Path to enterprise CIDR whitelist configuration YAML")
	managementCIDRsFlag := flag.String("management-cidrs", "", "Comma-separated list of management CIDRs to whitelist and bypass in eBPF fast-path")
	panicUnbanAllFlag := flag.Bool("panic-unban-all", false, "Emergency Break-Glass flush: immediately flush all banned and tarpit kernel eBPF maps and exit")
	mirrorSockPath := flag.String("mirror-sock", network.DefaultMirrorSocketPath, "Path to TLS Decryption Mirror UNIX domain socket")
	reaperInterval := flag.Duration("ban-reaper-interval", 15*time.Second, "Interval for dynamic eBPF ban TTL reaper")
	ifaceFlag := flag.String("interface", "", "Network interface for eBPF/XDP mitigation (e.g. eth0)")
	xdpModeFlag := flag.String("xdp-mode", "native", "eBPF/XDP driver attachment mode ('native' or 'generic')")
	controllerIPFlag := flag.String("controller-ip", "", "Controller IP address (auto-configures gRPC target)")
	gossipPortFlag := flag.Int("gossip-port", 7946, "Port for Memberlist Gossip threat replication")
	gossipJoinFlag := flag.String("gossip-join", "", "Initial Memberlist Gossip peer(s) to join (comma-separated host:port)")
	mgmtPortFlag := flag.Int("mgmt-port", 50052, "Port for dynamic rule management gRPC service (defaults to 127.0.0.1:50052)")
	mgmtListenFlag := flag.String("mgmt-listen", "", "Address or Unix socket path for dynamic rule management gRPC service (default: 127.0.0.1:<mgmt-port>)")
	enableRemoteMgmtFlag := flag.Bool("enable-remote-mgmt", false, "Explicitly permit binding dynamic rule management to remote/non-loopback network interfaces")
	mgmtSecretFlag := flag.String("mgmt-secret", "", "Authoritative pre-shared key or Bearer token for management gRPC service (or via COPSEC_MGMT_KEY env var)")
	mgmtTLSCertFlag := flag.String("mgmt-tls-cert", "", "Path to TLS certificate PEM for management gRPC service (required if remote management is enabled)")
	mgmtTLSKeyFlag := flag.String("mgmt-tls-key", "", "Path to TLS private key PEM for management gRPC service (required if remote management is enabled)")
	mgmtTLSCAFlag := flag.String("mgmt-tls-ca", "", "Path to Client CA certificate PEM for mutual TLS (mTLS) client verification")
	enableTarpitFlag := flag.Bool("enable-tarpit", true, "Enable Asymmetric Zero-Window XDP Tarpit engine")
	enableSynProxyFlag := flag.Bool("enable-syn-proxy", true, "Enable Stateful Kernel TCP SYN-Proxy mitigation")
	enableBGPFlag := flag.Bool("enable-bgp", false, "Enable Autonomous BGP-4 Anycast & RFC 7999 RTBH signaling engine")
	bgpPeerIPFlag := flag.String("bgp-peer-ip", "192.168.1.1", "Upstream BGP peer router IP address")
	bgpPeerPortFlag := flag.Int("bgp-peer-port", 179, "Upstream BGP peer port")
	bgpASFlag := flag.Uint("bgp-as", 65001, "Autonomous System Number (ASN) for local and upstream peer peering")
	bgpLocalASFlag := flag.Uint("bgp-local-as", 0, "Local Autonomous System Number (ASN, overrides --bgp-as)")
	bgpPeerASFlag := flag.Uint("bgp-peer-as", 0, "Upstream peer Autonomous System Number (ASN, overrides --bgp-as)")
	bgpRouterIDFlag := flag.String("bgp-router-id", "", "BGP Router ID (defaults to host IP or 192.168.1.8)")
	bgpRTBHThresholdPPS := flag.Uint64("bgp-rtbh-threshold-pps", 200000, "Ingress packet flood threshold to trigger upstream RTBH blackholing")
	bgpRecoveryDuration := flag.Duration("bgp-recovery-duration", 60*time.Second, "Quiet recovery duration before withdrawing RTBH blackhole")
	bgpBlackholeNextHop := flag.String("bgp-blackhole-next-hop", "192.0.2.1", "RFC 5735 / RFC 7999 blackhole next-hop IP")
	flag.Parse()

	if *panicUnbanAllFlag {
		flushed, err := ebpf.GetXDPEngine().EmergencyFlushAll()
		if err != nil {
			log.Fatalf("[PANIC_FLUSH_ERROR] Failed to execute emergency flush: %v", err)
		}
		log.Printf("[PANIC_FLUSH_SUCCESS] [ALERT] Break-Glass Emergency Flush completed. Purged %d banned/tarpit records from kernel maps.", flushed)
		os.Exit(0)
	}

	if *controllerIPFlag != "" {
		trimmed := strings.TrimSpace(*controllerIPFlag)
		if !strings.Contains(trimmed, ":") {
			*controllerAddr = trimmed + ":50051"
		} else {
			*controllerAddr = trimmed
		}
	}

	if *ifaceFlag != "" {
		resolvedIface := strings.TrimSpace(*ifaceFlag)
		if _, err := net.InterfaceByName(resolvedIface); err != nil {
			if _, err2 := net.InterfaceByName("enp0s3"); err2 == nil {
				log.Printf("[INFO] Interface %s not found on host; dynamically resolving to active VirtualBox interface 'enp0s3'", resolvedIface)
				resolvedIface = "enp0s3"
			} else {
				ifaces, _ := net.Interfaces()
				for _, ifc := range ifaces {
					if (ifc.Flags&net.FlagLoopback == 0) && (ifc.Flags&net.FlagUp != 0) {
						log.Printf("[INFO] Interface %s not found; dynamically resolving to active interface '%s'", resolvedIface, ifc.Name)
						resolvedIface = ifc.Name
						break
					}
				}
			}
		}
		ebpf.GetXDPEngine().SetInterfaceAndMode(resolvedIface, *xdpModeFlag)
	}

	if *enableSynProxyFlag {
		_ = ebpf.GetXDPEngine().EnableSynProxy(0)
		log.Println("[INFO] [FASTPATH] In-kernel Stateful TCP SYN-Proxy active defense enabled")
	}

	log.Println("[INFO] CoPSeC Ultra-Fast Edge Collector initializing (Hub-and-Spoke SIEM Ingestion)...")

	// 1. Identity & Auto-Enrollment
	identityMgr, err := LoadOrCreateIdentity(*nodeIdentityPath)
	if err != nil {
		log.Fatalf("[FATAL] Identity initialization failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 2. Offline Buffering & Autonomous Fallback Engine
	finalBufferPath := *bufferDbPath
	if err := os.MkdirAll(filepath.Dir(finalBufferPath), 0750); err != nil {
		finalBufferPath = "./buffer.db"
	}
	offlineBuffer, err := NewOfflineBuffer(finalBufferPath)
	if err != nil {
		log.Fatalf("[FATAL] Offline buffer initialization failed: %v", err)
	}
	defer offlineBuffer.Close()

	fallbackEngine := NewFallbackEngine(identityMgr.GetNodeID())

	// 3. gRPC Client for Controller Streaming
	grpcCfg := GrpcClientConfig{
		ServerAddress:   *controllerAddr,
		HeartbeatPeriod: 10 * time.Second,
		MaxBatchSize:    100,
	}
	controllerClient := NewControllerClient(grpcCfg, identityMgr, offlineBuffer)
	controllerClient.SetFallbackEngine(fallbackEngine)

	// 4. File Offsets & Whitelist
	finalOffsetPath := *offsetFilePath
	if err := os.MkdirAll(filepath.Dir(finalOffsetPath), 0750); err != nil {
		finalOffsetPath = "./offsets.json"
	}

	finalWhitelistPath := *whitelistPath
	if _, err := os.Stat(finalWhitelistPath); os.IsNotExist(err) {
		fallback := "../config/whitelist.json"
		if _, err := os.Stat(fallback); err == nil {
			finalWhitelistPath = fallback
		}
	}

	sources := []LogSourceConfig{
		{Source: "nginx", Path: *nginxLogPath},
		{Source: "auth", Path: *authLogPath},
		{Source: "syslog", Path: *syslogPath},
		{Source: "suricata", Path: *suricataLogPath},
		{Source: "snort", Path: *snortLogPath},
		{Source: "audit", Path: *auditLogPath},
	}

	collector := NewMultiLogCollector(sources, finalOffsetPath, finalWhitelistPath, controllerClient)
	fallbackEngine.SetWhitelistFilter(collector.GetFilter(), finalWhitelistPath)

	// 4b. Enterprise CIDR Whitelist Engine & eBPF Fast-Bypass
	cidrWhitelist := network.NewCIDRWhitelist()
	finalWhitelistYamlPath := *whitelistYamlPath
	if _, err := os.Stat(finalWhitelistYamlPath); os.IsNotExist(err) {
		fallbackYaml := "../config/whitelist.yaml"
		if _, err := os.Stat(fallbackYaml); err == nil {
			finalWhitelistYamlPath = fallbackYaml
		}
	}
	if err := cidrWhitelist.LoadFromFile(finalWhitelistYamlPath); err != nil {
		if err := cidrWhitelist.LoadFromFile(finalWhitelistPath); err != nil {
			log.Printf("[INFO] CIDR Whitelist initialized with %d default RFC1918/loopback subnets", len(cidrWhitelist.ListCIDRs()))
		}
	}
	if *managementCIDRsFlag != "" {
		for _, cidr := range strings.Split(*managementCIDRsFlag, ",") {
			trimmed := strings.TrimSpace(cidr)
			if trimmed != "" {
				cidrWhitelist.AddCIDR(trimmed, "CLI Management Whitelist")
				_ = ebpf.GetXDPEngine().AddWhitelistIP(trimmed)
			}
		}
		log.Printf("[INFO] Ingested user management CIDRs into fast-path bypass: %s", *managementCIDRsFlag)
	}
	dpiInspector := dpi.GetDefaultInspector()
	dpiInspector.SetWhitelist(cidrWhitelist)

	// 5. Start Defensive Subsystems (FIM, Tarpit, Honeypot, YARA, Integrity Guard, DNS Sinkhole)
	fimEngine := healing.GetDefaultFIMEngine()
	go fimEngine.StartWatchLoop(ctx, 30*time.Second)

	// 5b. Start Real-Time Fleet Telemetry Heartbeat Engine
	hbWorker := network.NewHeartbeatWorker(network.HeartbeatConfig{
		NodeID:             identityMgr.GetNodeID(),
		ControllerEndpoint: *controllerAddr,
		Interval:           10 * time.Second,
	})
	hbWorker.Start(ctx)
	defer hbWorker.Stop()

	// 5c. Start Dynamic eBPF Ban TTL Reaper & Audit Streamer
	banManager := network.NewBanManager(*controllerAddr)
	banManager.StartBanReaper(ctx, *reaperInterval)

	// 5d. Start Transparent TLS Decryption Mirror Ingress Socket
	mirrorServer := network.NewTLSMirrorServer(*mirrorSockPath, dpiInspector)
	if err := mirrorServer.Start(ctx); err != nil {
		log.Printf("[WARN] TLS Mirror Socket failed to start on %s: %v", *mirrorSockPath, err)
	} else {
		defer mirrorServer.Stop()
	}

	// 5e. Start Distributed Threat Synchronization (Memberlist Gossip Mesh)
	var gossipPeers []string
	if *gossipJoinFlag != "" {
		for _, p := range strings.Split(*gossipJoinFlag, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				gossipPeers = append(gossipPeers, trimmed)
			}
		}
	}
	gossipCluster, err := cluster.NewGossipCluster(cluster.GossipConfig{
		NodeID:   identityMgr.GetNodeID(),
		BindPort: *gossipPortFlag,
		Peers:    gossipPeers,
	})
	if err != nil {
		log.Printf("[WARN] Gossip cluster initialization note: %v", err)
	} else {
		defer gossipCluster.Shutdown()
	}

	// 5f. Start Dynamic Rule Reloader Management Endpoint (Hardened loopback/TLS gRPC)
	dynamicEngine := dpi.NewDynamicEngine(dpi.GetEmbeddedSignatures())

	mgmtListenAddr := strings.TrimSpace(*mgmtListenFlag)
	if mgmtListenAddr == "" {
		mgmtListenAddr = fmt.Sprintf("127.0.0.1:%d", *mgmtPortFlag)
	}

	mgmtCfg := &management.Config{
		ListenAddr:       mgmtListenAddr,
		EnableRemoteMgmt: *enableRemoteMgmtFlag,
		AuthSecret:       *mgmtSecretFlag,
		TLSCertFile:      *mgmtTLSCertFlag,
		TLSKeyFile:       *mgmtTLSKeyFlag,
		ClientCAFile:     *mgmtTLSCAFlag,
	}

	mgmtServer, err := management.NewServer(mgmtCfg, dpi.NewManagementServer(dynamicEngine))
	if err != nil {
		log.Printf("[MANAGEMENT_GRPC] [WARN] Hardened management server initialization note: %v", err)
	} else {
		mgmtServer.Start()
		defer mgmtServer.Stop()
	}

	if *enableTarpitFlag {
		tarpitEngine := tarpit.GetDefaultTarpit()
		go func() {
			if err := tarpitEngine.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("[WARN] Tarpit engine runtime note: %v", err)
			}
		}()
		defer tarpitEngine.Close()
		log.Println("[INFO] [FASTPATH] Asymmetric XDP Zero-Window Tarpit defense active")
	}

	honeypotEngine := honeypot.GetDefaultShadowHoneypot()
	honeypotEngine.SetEventHandler(func(interaction honeypot.HoneypotInteraction) {
		if controllerClient != nil {
			ev := &copsecproto.LogEvent{
				Source:           "honeypot",
				RawLine:          fmt.Sprintf("[HONEYPOT_DECEPTION: %s] %s (is_honeypot=true)", interaction.TrapType, interaction.PayloadSummary),
				ClientIp:         interaction.ClientIP,
				ThreatScore:      95,
				RuleId:           fmt.Sprintf("honeypot_%s", strings.ToLower(interaction.TrapType)),
				MitreTechniqueId: interaction.MitreTechniqueID,
				TimestampMs:      interaction.TimestampMs,
			}
			controllerClient.Submit(ev)
		}
	})
	go func() {
		if err := honeypotEngine.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[WARN] Honeypot engine runtime note: %v", err)
		}
	}()
	defer honeypotEngine.Close()

	if ig := ebpf.GetDefaultIntegrityGuard(); ig != nil {
		log.Println("[INFO]  eBPF Kernel Map & Driver Integrity Guard active")
	}
	if sh := dns.GetDefaultSinkhole(); sh != nil {
		sh.SetEventHandler(func(ev dns.DNSSinkholeEvent) {
			if controllerClient != nil {
				logEv := &copsecproto.LogEvent{
					Source:           "dns_sinkhole",
					RawLine:          fmt.Sprintf("[DNS_SINKHOLE] domain=%s anomaly=%s entropy=%.2f details=%s (caller_pid=%d proc=%s)", ev.Domain, ev.AnomalyType, ev.Entropy, ev.Details, ev.CallerPID, ev.ProcessName),
					ClientIp:         "127.0.0.1",
					ThreatScore:      int32(ev.ThreatScore),
					RuleId:           fmt.Sprintf("dns_%s", strings.ToLower(ev.AnomalyType)),
					MitreTechniqueId: ev.MitreID,
					TimestampMs:      ev.TimestampMs,
				}
				controllerClient.Submit(logEv)
			}
		})
		log.Println("[INFO]  Autonomous DNS Sinkhole active")
	}
	if yr := yara.GetDefaultScanner(); yr != nil {
		log.Println("[INFO]  Memory & Payload YARA Scanner active")
	}

	// 5g. Autonomous BGP-4 Anycast & RFC 7999 RTBH Signaling Engine
	var bgpSpeaker *bgp.Speaker
	if *enableBGPFlag {
		routerID := *bgpRouterIDFlag
		if routerID == "" {
			routerID = "192.168.1.8"
		}
		localAS := uint32(*bgpASFlag)
		if *bgpLocalASFlag != 0 {
			localAS = uint32(*bgpLocalASFlag)
		}
		peerAS := uint32(*bgpASFlag)
		if *bgpPeerASFlag != 0 {
			peerAS = uint32(*bgpPeerASFlag)
		}
		bgpCfg := bgp.Config{
			Enabled:          true,
			LocalAS:          localAS,
			PeerAS:           peerAS,
			RouterID:         routerID,
			PeerAddress:      *bgpPeerIPFlag,
			PeerPort:         *bgpPeerPortFlag,
			RTBHThresholdPPS: *bgpRTBHThresholdPPS,
			RecoveryDuration: *bgpRecoveryDuration,
			BlackholeNextHop: *bgpBlackholeNextHop,
		}
		bgpSpeaker = bgp.NewSpeaker(bgpCfg)
		if err := bgpSpeaker.Start(ctx); err != nil {
			log.Printf("[WARN] BGP Speaker failed to start: %v", err)
		} else {
			defer bgpSpeaker.Stop()
			log.Printf("[INFO]  Autonomous BGP-4 Anycast & RFC 7999 RTBH Engine active (Local: AS%d, Peer: AS%d@%s:%d, Threshold: %d PPS, Recovery: %v)",
				localAS, peerAS, *bgpPeerIPFlag, *bgpPeerPortFlag, *bgpRTBHThresholdPPS, *bgpRecoveryDuration)
		}
	}

	// 5h. Attach Kernel RingBuffer Drop Telemetry Processor if pinned map exists
	pinRingbufCandidates := []string{
		filepath.Join(ebpf.DefaultBPFPinPath, "telemetry_ringbuf"),
		"/sys/fs/bpf/telemetry_ringbuf",
	}
	for _, pinPath := range pinRingbufCandidates {
		if rbMap, err := ciliumEbpf.LoadPinnedMap(pinPath, nil); err == nil {
			telemetryProc, err := bpf.NewReader(&bpf.TelemetryObjects{TelemetryRingbuf: rbMap}, bpf.FuncBus(func(event bpf.DropEvent) {
				if bgpSpeaker != nil && (event.DropReason == bpf.DropReasonRateLimit || event.DropReason == bpf.DropReasonSynFlood) {
					bgpSpeaker.RecordIngressMetrics(event.IP().String(), *bgpRTBHThresholdPPS)
				}
				if controllerClient != nil {
					mitreID := ""
					if ttpInfo, ok := ttp.LookupByRule(event.DropReason.String()); ok {
						mitreID = ttpInfo.ID
					}
					ev := &copsecproto.LogEvent{
						Source:           "ebpf_xdp",
						RawLine:          fmt.Sprintf("[XDP_DROP] src_ip=%s src_port=%d proto=%d reason=%s target_comm=KERNEL_FASTPATH_DROP", event.IP().String(), event.SrcPort, event.Protocol, event.DropReason.String()),
						ClientIp:         event.IP().String(),
						ThreatScore:      90,
						RuleId:           fmt.Sprintf("xdp_%s", strings.ToLower(event.DropReason.String())),
						MitreTechniqueId: mitreID,
						TimestampMs:      int64(event.TimestampNs / 1000000),
						TargetPid:        0,
						TargetComm:       "KERNEL_FASTPATH_DROP [PID: 0]",
					}
					controllerClient.Submit(ev)
				}
			}))
			if err == nil {
				telemetryProc.Start(ctx)
				defer telemetryProc.Close()
				log.Printf("[INFO] [FASTPATH] Zero-Copy Kernel Telemetry RingBuffer processor attached at %s", pinPath)
				break
			}
		}
	}

	// 5h. Attach Live Forensic Raw Packet Stream RingBuffer Processor
	pinRawRingbufCandidates := []string{
		filepath.Join(ebpf.DefaultBPFPinPath, "raw_packet_ringbuf"),
		"/sys/fs/bpf/raw_packet_ringbuf",
	}
	var rawRbMap *ciliumEbpf.Map
	for _, pinPath := range pinRawRingbufCandidates {
		if m, err := ciliumEbpf.LoadPinnedMap(pinPath, nil); err == nil {
			rawRbMap = m
			log.Printf("[INFO] Attached to pinned raw_packet_ringbuf at %s", pinPath)
			break
		}
	}
	if rawRbMap == nil {
		rawRbMap = ebpf.GetXDPEngine().GetRawPacketMap()
	}
	if rawRbMap != nil {
		rawProc, err := bpf.NewRawPacketProcessor(rawRbMap, bpf.RawPacketFuncBus(func(sample bpf.RawPacketSample) {
			if controllerClient != nil {
				srcIP := sample.SrcIPString()
				dstIP := sample.DstIPString()
				mitreID := ""
				if ttpInfo, ok := ttp.LookupByRule(sample.DropReasonString()); ok {
					mitreID = ttpInfo.ID
				}
				targetPid := int32(0)
				targetComm := "KERNEL_FASTPATH_DROP [PID: 0]"
				if sample.DropReason == 0 {
					// Packet reached host network stack - correlate with active sockets
					if proc, ok := ebpf.GetDefaultEDREngine().LookupProcessBySocket(srcIP, int(sample.SrcPort()), dstIP, int(sample.DstPort())); ok && proc != nil {
						targetPid = int32(proc.PID)
						targetComm = fmt.Sprintf("%s [PID: %d]", proc.Comm, proc.PID)
					}
				}
				ev := &copsecproto.LogEvent{
					Source:           "ebpf_pcap",
					RawLine:          fmt.Sprintf("[PCAP_SAMPLE] src_ip=%s src_port=%d proto=%d reason=%s cap_len=%d wire_len=%d hex=%s target_comm=%s",
						srcIP, sample.SrcPort(), sample.Protocol(), sample.DropReasonString(), sample.CaptureLen, sample.WireLen, sample.HexString(), targetComm),
					ClientIp:         srcIP,
					ThreatScore:      85,
					RuleId:           fmt.Sprintf("pcap_%s", strings.ToLower(sample.DropReasonString())),
					MitreTechniqueId: mitreID,
					TimestampMs:      int64(sample.TimestampNs / 1000000),
					TargetPid:        targetPid,
					TargetComm:       targetComm,
				}
				controllerClient.Submit(ev)
			}
		}))
		if err == nil {
			rawProc.Start(ctx)
			defer rawProc.Close()
			log.Println("[INFO]  Live Forensic Raw Packet RingBuffer stream processor attached")
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		sig := <-sigChan
		log.Printf("[INFO] Signal %v received. Initiating graceful collector shutdown...", sig)
		cancel()
	}()

	collector.Start(ctx)
}
