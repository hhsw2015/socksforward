package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	webPort := flag.Int("port", 8080, "Web 管理端口")
	configPath := flag.String("config", "config.json", "配置文件路径")
	defaultPassword := flag.String("password", "123456", "Web 管理密码")
	udpTimeout := flag.Int("timeout", 30, "UDP 会话空闲超时时间(秒)")
	flag.Parse()

	if *defaultPassword == "" {
		log.Fatal("默认密码不能为空")
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	manager := NewManager(time.Duration(*udpTimeout) * time.Second)
	manager.Apply(cfg)

	server := NewServer(cfg, *configPath, manager, *defaultPassword)
	addr := fmt.Sprintf("0.0.0.0:%d", *webPort)
	log.Printf("Web 管理监听: %s", addr)
	if err := http.ListenAndServe(addr, server.Handler()); err != nil {
		log.Fatalf("Web 服务启动失败: %v", err)
	}
}

type Config struct {
	Socks5  Socks5Config  `json:"socks5"`
	Forward ForwardConfig `json:"forward"`
}

type Socks5Config struct {
	Nodes []Socks5Node `json:"nodes"`
}

type Socks5Node struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type ForwardConfig struct {
	Rules []ForwardRule `json:"rules"`
}

type ForwardRule struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Proto        string `json:"proto"`
	Listen       string `json:"listen"`
	Target       string `json:"target"`
	Socks5NodeID string `json:"socks5NodeId"`
	Enabled      bool   `json:"enabled"`
}

func DefaultConfig() *Config {
	return &Config{
		Socks5: Socks5Config{
			Nodes: []Socks5Node{},
		},
		Forward: ForwardConfig{
			Rules: []ForwardRule{},
		},
	}
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		cfg := DefaultConfig()
		if err := SaveConfig(path, cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	if len(b) == 0 {
		cfg := DefaultConfig()
		if err := SaveConfig(path, cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, err
	}

	if cfg.Socks5.Nodes == nil {
		cfg.Socks5.Nodes = []Socks5Node{}
	}
	if cfg.Forward.Rules == nil {
		cfg.Forward.Rules = []ForwardRule{}
	}
	return cfg, nil
}

func SaveConfig(path string, cfg *Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func CloneConfig(cfg *Config) *Config {
	if cfg == nil {
		return DefaultConfig()
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return DefaultConfig()
	}
	var out Config
	if err := json.Unmarshal(b, &out); err != nil {
		return DefaultConfig()
	}
	return &out
}

type Auth struct {
	Username string
	Password string
}

func DialTCP(proxyAddr, targetAddr string, auth *Auth, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	if err := Handshake(conn, auth); err != nil {
		conn.Close()
		return nil, err
	}
	if err := Connect(conn, targetAddr); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func UDPAssociate(proxyAddr string, auth *Auth, timeout time.Duration) (net.Conn, *net.UDPAddr, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, nil, err
	}
	if err := Handshake(conn, auth); err != nil {
		conn.Close()
		return nil, nil, err
	}
	relayAddr, err := Associate(conn, "0.0.0.0:0")
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, relayAddr, nil
}

func Handshake(conn net.Conn, auth *Auth) error {
	methods := []byte{0x00}
	if auth != nil && auth.Username != "" {
		methods = []byte{0x02}
	}
	req := []byte{0x05, byte(len(methods))}
	req = append(req, methods...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return errors.New("SOCKS5 版本不支持")
	}
	switch resp[1] {
	case 0x00:
		return nil
	case 0x02:
		return authUserPass(conn, auth)
	default:
		return errors.New("SOCKS5 认证方式不支持")
	}
}

func Connect(conn net.Conn, targetAddr string) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteByte(0x05)
	buf.WriteByte(0x01)
	buf.WriteByte(0x00)
	if err := writeAddr(&buf, host, port); err != nil {
		return err
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return err
	}
	return readReply(conn)
}

func Associate(conn net.Conn, addr string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteByte(0x05)
	buf.WriteByte(0x03)
	buf.WriteByte(0x00)
	if err := writeAddr(&buf, host, port); err != nil {
		return nil, err
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	return readUDPReply(conn)
}

func EncodeUDPRequest(targetAddr string, payload []byte) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x00, 0x00})
	if err := writeAddr(&buf, host, port); err != nil {
		return nil, err
	}
	buf.Write(payload)
	return buf.Bytes(), nil
}

func DecodeUDPResponse(b []byte) ([]byte, string, error) {
	if len(b) < 4 {
		return nil, "", errors.New("UDP 响应过短")
	}
	if b[2] != 0x00 {
		return nil, "", errors.New("UDP FRAG 不支持")
	}
	r := bytes.NewReader(b[3:])
	addr, err := readAddrPort(r)
	if err != nil {
		return nil, "", err
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		return nil, "", err
	}
	return rest, addr, nil
}

func authUserPass(conn net.Conn, auth *Auth) error {
	if auth == nil {
		return errors.New("需要用户名密码")
	}
	if len(auth.Username) > 255 || len(auth.Password) > 255 {
		return errors.New("用户名或密码过长")
	}
	req := []byte{0x01, byte(len(auth.Username))}
	req = append(req, []byte(auth.Username)...)
	req = append(req, byte(len(auth.Password)))
	req = append(req, []byte(auth.Password)...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errors.New("用户名密码认证失败")
	}
	return nil
}

func writeAddr(buf *bytes.Buffer, host string, port int) error {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf.WriteByte(0x01)
			buf.Write(ip4)
		} else {
			buf.WriteByte(0x04)
			buf.Write(ip.To16())
		}
	} else {
		if len(host) > 255 {
			return errors.New("域名过长")
		}
		buf.WriteByte(0x03)
		buf.WriteByte(byte(len(host)))
		buf.WriteString(host)
	}
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	buf.Write(p)
	return nil
}

func readReply(conn net.Conn) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return errors.New("SOCKS5 响应版本错误")
	}
	if head[1] != 0x00 {
		return fmt.Errorf("SOCKS5 连接失败: %d", head[1])
	}
	_, err := readAddrPortFrom(conn, head[3])
	return err
}

func readUDPReply(conn net.Conn) (*net.UDPAddr, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	if head[0] != 0x05 {
		return nil, errors.New("SOCKS5 响应版本错误")
	}
	if head[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 UDP 关联失败: %d", head[1])
	}
	addr, err := readAddrPortFrom(conn, head[3])
	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr("udp", addr)
}

func readAddrPortFrom(r io.Reader, atyp byte) (string, error) {
	host, port, err := readAddrPortWithAtyp(r, atyp)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func readAddrPort(r io.Reader) (string, error) {
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(r, atyp); err != nil {
		return "", err
	}
	host, port, err := readAddrPortWithAtyp(r, atyp[0])
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func readAddrPortWithAtyp(r io.Reader, atyp byte) (string, int, error) {
	var host string
	switch atyp {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", 0, err
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	default:
		return "", 0, errors.New("地址类型不支持")
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", 0, err
	}
	port := int(binary.BigEndian.Uint16(portBuf))
	return host, port, nil
}

type Manager struct {
	mu         sync.Mutex
	runners    map[string]*ruleRunner
	lastErrors map[string]string
	udpTimeout time.Duration
}

func NewManager(udpTimeout time.Duration) *Manager {
	return &Manager{
		runners:    make(map[string]*ruleRunner),
		lastErrors: make(map[string]string),
		udpTimeout: udpTimeout,
	}
}

func (m *Manager) GetRuleError(ruleID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErrors[ruleID]
}

func (m *Manager) Apply(cfg *Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, runner := range m.runners {
		runner.Stop()
		log.Printf("规则已停止: %s %s %s -> %s (节点: %s)", runner.rule.ID, runner.rule.Proto, runner.rule.Listen, runner.rule.Target, runner.rule.Socks5NodeID)
	}
	m.runners = make(map[string]*ruleRunner)
	m.lastErrors = make(map[string]string)
	if cfg == nil {
		return
	}
	nodes := make(map[string]Socks5Node)
	for _, node := range cfg.Socks5.Nodes {
		nodes[node.ID] = node
	}
	for _, rule := range cfg.Forward.Rules {
		if !rule.Enabled {
			continue
		}
		node, ok := nodes[rule.Socks5NodeID]
		if !ok {
			msg := fmt.Sprintf("未找到 SOCKS5 节点: %s", rule.Socks5NodeID)
			log.Printf("规则 %s 错误: %s", rule.ID, msg)
			m.lastErrors[rule.ID] = msg
			continue
		}
		runner, err := startRule(rule, node, m.udpTimeout)
		if err != nil {
			log.Printf("规则 %s 启动失败: %v", rule.ID, err)
			m.lastErrors[rule.ID] = err.Error()
			continue
		}
		m.runners[rule.ID] = runner
	}
}

type ruleRunner struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
	rule   ForwardRule
}

func (r *ruleRunner) Stop() {
	if r == nil {
		return
	}
	r.cancel()
	r.wg.Wait()
}

func startRule(rule ForwardRule, node Socks5Node, udpTimeout time.Duration) (*ruleRunner, error) {
	if rule.Listen == "" || rule.Target == "" {
		return nil, errors.New("listen 或 target 为空")
	}
	if rule.Proto == "" {
		return nil, errors.New("proto 为空")
	}
	proto := strings.ToLower(rule.Proto)
	ctx, cancel := context.WithCancel(context.Background())
	runner := &ruleRunner{cancel: cancel, rule: rule}

	if proto == "tcp" || proto == "both" {
		ln, err := net.Listen("tcp", rule.Listen)
		if err != nil {
			cancel()
			return nil, err
		}
		runner.wg.Add(1)
		go func() {
			defer runner.wg.Done()
			<-ctx.Done()
			ln.Close()
		}()
		runner.wg.Add(1)
		go func() {
			defer runner.wg.Done()
			acceptTCP(ctx, ln, rule, node)
		}()
	}

	if proto == "udp" || proto == "both" {
		udpAddr, err := net.ResolveUDPAddr("udp", rule.Listen)
		if err != nil {
			cancel()
			return nil, err
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			cancel()
			return nil, err
		}
		runner.wg.Add(1)
		go func() {
			defer runner.wg.Done()
			<-ctx.Done()
			conn.Close()
		}()
		runner.wg.Add(1)
		go func() {
			defer runner.wg.Done()
			serveUDP(ctx, conn, rule, node, udpTimeout)
		}()
	}

	if proto != "tcp" && proto != "udp" && proto != "both" {
		cancel()
		return nil, errors.New("proto 仅支持 tcp/udp/both")
	}
	log.Printf("规则已启动: %s %s %s -> %s (节点: %s)", rule.ID, rule.Proto, rule.Listen, rule.Target, node.ID)
	return runner, nil
}

func acceptTCP(ctx context.Context, ln net.Listener, rule ForwardRule, node Socks5Node) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("TCP 接受失败: %v", err)
				continue
			}
		}
		go handleTCP(conn, rule, node)
	}
}

func handleTCP(conn net.Conn, rule ForwardRule, node Socks5Node) {
	defer conn.Close()
	auth := nodeAuth(node)
	proxyConn, err := DialTCP(node.Address, rule.Target, auth, 10*time.Second)
	if err != nil {
		log.Printf("TCP 连接失败: %v", err)
		return
	}
	defer proxyConn.Close()
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(proxyConn, conn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, proxyConn)
		done <- struct{}{}
	}()
	<-done
}

type udpSession struct {
	clientAddr *net.UDPAddr
	tcpConn    net.Conn
	relayConn  *net.UDPConn
	lastActive time.Time
	closeOnce  sync.Once
	done       chan struct{}
}

func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		if s.relayConn != nil {
			s.relayConn.Close()
		}
		if s.tcpConn != nil {
			s.tcpConn.Close()
		}
		close(s.done)
	})
}

func serveUDP(ctx context.Context, conn *net.UDPConn, rule ForwardRule, node Socks5Node, timeout time.Duration) {
	sessions := make(map[string]*udpSession)
	var mu sync.Mutex
	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	go func() {
		for {
			select {
			case <-cleanupTicker.C:
				expired := time.Now().Add(-timeout)
				mu.Lock()
				for key, sess := range sessions {
					if sess.lastActive.Before(expired) {
						sess.close()
						delete(sessions, key)
					}
				}
				mu.Unlock()
			case <-ctx.Done():
				mu.Lock()
				for key, sess := range sessions {
					sess.close()
					delete(sessions, key)
				}
				mu.Unlock()
				return
			}
		}
	}()

	buf := make([]byte, 64*1024)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("UDP 读取失败: %v", err)
				continue
			}
		}
		payload := append([]byte(nil), buf[:n]...)
		key := addr.String()
		mu.Lock()
		sess, ok := sessions[key]
		mu.Unlock()

		if ok {
			select {
			case <-sess.done:
				mu.Lock()
				delete(sessions, key)
				mu.Unlock()
				ok = false
			default:
			}
		}

		if !ok {
			newSess, err := newUDPSession(addr, rule, node, conn)
			if err != nil {
				log.Printf("UDP 创建会话失败: %v", err)
				continue
			}
			mu.Lock()
			sessions[key] = newSess
			sess = newSess
			mu.Unlock()
		}
		sess.lastActive = time.Now()
		packet, err := EncodeUDPRequest(rule.Target, payload)
		if err != nil {
			log.Printf("UDP 打包失败: %v", err)
			continue
		}
		if _, err := sess.relayConn.Write(packet); err != nil {
			log.Printf("UDP 发送失败: %v", err)
			sess.close()
			mu.Lock()
			delete(sessions, key)
			mu.Unlock()
		}
	}
}

func newUDPSession(clientAddr *net.UDPAddr, rule ForwardRule, node Socks5Node, listener *net.UDPConn) (*udpSession, error) {
	auth := nodeAuth(node)
	tcpConn, relayAddr, err := UDPAssociate(node.Address, auth, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if relayAddr.IP == nil || relayAddr.IP.IsUnspecified() {
		host, _, err := net.SplitHostPort(node.Address)
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		resolved, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(relayAddr.Port)))
		if err != nil {
			tcpConn.Close()
			return nil, err
		}
		relayAddr = resolved
	}
	relayConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		tcpConn.Close()
		return nil, err
	}
	sess := &udpSession{
		clientAddr: clientAddr,
		tcpConn:    tcpConn,
		relayConn:  relayConn,
		lastActive: time.Now(),
		done:       make(chan struct{}),
	}

	// 监控 TCP 连接状态，一旦断开立即终止 UDP 会话
	go func() {
		defer sess.close()
		io.Copy(io.Discard, tcpConn)
	}()

	go relayToClient(sess, rule, listener)
	return sess, nil
}

func relayToClient(sess *udpSession, rule ForwardRule, listener *net.UDPConn) {
	buf := make([]byte, 64*1024)
	for {
		n, err := sess.relayConn.Read(buf)
		if err != nil {
			sess.close()
			return
		}
		payload, _, err := DecodeUDPResponse(buf[:n])
		if err != nil {
			continue
		}
		if len(payload) == 0 {
			continue
		}
		_, _ = listener.WriteToUDP(payload, sess.clientAddr)
	}
}

func nodeAuth(node Socks5Node) *Auth {
	if node.Username == "" && node.Password == "" {
		return nil
	}
	return &Auth{
		Username: node.Username,
		Password: node.Password,
	}
}

type Server struct {
	mu         sync.RWMutex
	cfg        *Config
	configPath string
	forward    *Manager
	sessions   map[string]struct{}
	sessionsMu sync.Mutex
	password   string
}

func NewServer(cfg *Config, configPath string, manager *Manager, password string) *Server {
	return &Server{
		cfg:        cfg,
		configPath: configPath,
		forward:    manager,
		sessions:   make(map[string]struct{}),
		password:   password,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("/nodes/add", s.requireAuth(s.handleNodeAdd))
	mux.HandleFunc("/nodes/update", s.requireAuth(s.handleNodeUpdate))
	mux.HandleFunc("/nodes/delete", s.requireAuth(s.handleNodeDelete))
	mux.HandleFunc("/rules/add", s.requireAuth(s.handleRuleAdd))
	mux.HandleFunc("/rules/update", s.requireAuth(s.handleRuleUpdate))
	mux.HandleFunc("/rules/delete", s.requireAuth(s.handleRuleDelete))
	mux.HandleFunc("/rules/toggle", s.requireAuth(s.handleRuleToggle))
	mux.HandleFunc("/", s.requireAuth(s.handleIndex))
	return mux
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.isAuthed(r) {
			next(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func (s *Server) isAuthed(r *http.Request) bool {
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		return false
	}
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	_, ok := s.sessions[cookie.Value]
	return ok
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			renderLogin(w, "表单解析失败")
			return
		}
		password := r.FormValue("password")
		if password != s.password {
			renderLogin(w, "密码错误")
			return
		}
		token, err := newToken()
		if err != nil {
			renderLogin(w, "生成会话失败")
			return
		}
		s.sessionsMu.Lock()
		s.sessions[token] = struct{}{}
		s.sessionsMu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
		})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderLogin(w, "")
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		s.sessionsMu.Lock()
		delete(s.sessions, cookie.Value)
		s.sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	s.mu.RLock()
	ruleErrors := make(map[string]string)
	if s.forward != nil {
		for _, rule := range s.cfg.Forward.Rules {
			if rule.Enabled {
				if err := s.forward.GetRuleError(rule.ID); err != "" {
					ruleErrors[rule.ID] = err
				}
			}
		}
	}
	data := pageData{
		Nodes:      append([]Socks5Node(nil), s.cfg.Socks5.Nodes...),
		Rules:      append([]ForwardRule(nil), s.cfg.Forward.Rules...),
		RuleErrors: ruleErrors,
		Message:    msg,
	}
	s.mu.RUnlock()
	renderIndex(w, data)
}

func (s *Server) handleNodeAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectMsg(w, r, "节点名称不能为空")
		return
	}
	address := strings.TrimSpace(r.FormValue("address"))
	if address == "" {
		redirectMsg(w, r, "节点地址不能为空")
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	err := s.updateConfig(func(cfg *Config) error {
		if nodeNameExists(cfg, name, "") {
			return fmt.Errorf("节点名称已存在")
		}
		id, err := newID()
		if err != nil {
			return err
		}
		cfg.Socks5.Nodes = append(cfg.Socks5.Nodes, Socks5Node{
			ID:       id,
			Name:     name,
			Address:  address,
			Username: username,
			Password: password,
		})
		return nil
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	redirectMsg(w, r, "节点已添加")
}

func (s *Server) handleNodeUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	name := strings.TrimSpace(r.FormValue("name"))
	address := strings.TrimSpace(r.FormValue("address"))
	if id == "" || address == "" {
		redirectMsg(w, r, "节点或地址不能为空")
		return
	}
	if name == "" {
		redirectMsg(w, r, "节点名称不能为空")
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	err := s.updateConfig(func(cfg *Config) error {
		if nodeNameExists(cfg, name, id) {
			return fmt.Errorf("节点名称已存在")
		}
		for i, node := range cfg.Socks5.Nodes {
			if node.ID == id {
				cfg.Socks5.Nodes[i].Name = name
				cfg.Socks5.Nodes[i].Address = address
				cfg.Socks5.Nodes[i].Username = username
				cfg.Socks5.Nodes[i].Password = password
				return nil
			}
		}
		return fmt.Errorf("节点不存在")
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	redirectMsg(w, r, "节点已更新")
}

func (s *Server) handleNodeDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
		redirectMsg(w, r, "节点 ID 不能为空")
		return
	}
	err := s.updateConfig(func(cfg *Config) error {
		for _, rule := range cfg.Forward.Rules {
			if rule.Socks5NodeID == id {
				return fmt.Errorf("已有规则使用该节点")
			}
		}
		for i, node := range cfg.Socks5.Nodes {
			if node.ID == id {
				cfg.Socks5.Nodes = append(cfg.Socks5.Nodes[:i], cfg.Socks5.Nodes[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("节点不存在")
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	redirectMsg(w, r, "节点已删除")
}

func (s *Server) handleRuleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectMsg(w, r, "规则名称不能为空")
		return
	}
	proto := strings.ToLower(strings.TrimSpace(r.FormValue("proto")))
	listen := strings.TrimSpace(r.FormValue("listen"))
	target := strings.TrimSpace(r.FormValue("target"))
	nodeID := strings.TrimSpace(r.FormValue("socks5NodeId"))
	enabled := r.FormValue("enabled") == "on"
	if listen == "" || target == "" || nodeID == "" {
		redirectMsg(w, r, "规则字段不能为空")
		return
	}
	if proto != "tcp" && proto != "udp" && proto != "both" {
		redirectMsg(w, r, "协议仅支持 tcp/udp/both")
		return
	}

	err := s.updateConfig(func(cfg *Config) error {
		if ruleNameExists(cfg, name, "") {
			return fmt.Errorf("规则名称已存在")
		}
		id, err := newID()
		if err != nil {
			return err
		}
		if !nodeExists(cfg, nodeID) {
			return fmt.Errorf("SOCKS5 节点不存在")
		}
		cfg.Forward.Rules = append(cfg.Forward.Rules, ForwardRule{
			ID:           id,
			Name:         name,
			Proto:        proto,
			Listen:       listen,
			Target:       target,
			Socks5NodeID: nodeID,
			Enabled:      enabled,
		})
		return nil
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	redirectMsg(w, r, "规则已添加")
}

func (s *Server) handleRuleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		redirectMsg(w, r, "规则名称不能为空")
		return
	}
	proto := strings.ToLower(strings.TrimSpace(r.FormValue("proto")))
	listen := strings.TrimSpace(r.FormValue("listen"))
	target := strings.TrimSpace(r.FormValue("target"))
	nodeID := strings.TrimSpace(r.FormValue("socks5NodeId"))
	enabledProvided := r.FormValue("enabled") != ""
	enabled := r.FormValue("enabled") == "on"
	if id == "" || listen == "" || target == "" || nodeID == "" {
		redirectMsg(w, r, "规则字段不能为空")
		return
	}
	if proto != "tcp" && proto != "udp" && proto != "both" {
		redirectMsg(w, r, "协议仅支持 tcp/udp/both")
		return
	}
	err := s.updateConfig(func(cfg *Config) error {
		if ruleNameExists(cfg, name, id) {
			return fmt.Errorf("规则名称已存在")
		}
		if !nodeExists(cfg, nodeID) {
			return fmt.Errorf("SOCKS5 节点不存在")
		}
		for i, rule := range cfg.Forward.Rules {
			if rule.ID == id {
				cfg.Forward.Rules[i].Name = name
				cfg.Forward.Rules[i].Proto = proto
				cfg.Forward.Rules[i].Listen = listen
				cfg.Forward.Rules[i].Target = target
				cfg.Forward.Rules[i].Socks5NodeID = nodeID
				if enabledProvided {
					cfg.Forward.Rules[i].Enabled = enabled
				}
				return nil
			}
		}
		return fmt.Errorf("规则不存在")
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	redirectMsg(w, r, "规则已更新")
}

func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	err := s.updateConfig(func(cfg *Config) error {
		for i, rule := range cfg.Forward.Rules {
			if rule.ID == id {
				cfg.Forward.Rules = append(cfg.Forward.Rules[:i], cfg.Forward.Rules[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("规则不存在")
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	redirectMsg(w, r, "规则已删除")
}

func (s *Server) handleRuleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectMsg(w, r, "表单解析失败")
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	err := s.updateConfig(func(cfg *Config) error {
		for i, rule := range cfg.Forward.Rules {
			if rule.ID == id {
				cfg.Forward.Rules[i].Enabled = !rule.Enabled
				return nil
			}
		}
		return fmt.Errorf("规则不存在")
	})
	if err != nil {
		redirectMsg(w, r, err.Error())
		return
	}
	errMsg := ""
	if s.forward != nil {
		if errStr := s.forward.GetRuleError(id); errStr != "" {
			errMsg = " (启动失败: " + errStr + ")"
		}
	}
	redirectMsg(w, r, "规则状态已更新"+errMsg)
}

func (s *Server) updateConfig(fn func(cfg *Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(s.cfg); err != nil {
		return err
	}
	if err := SaveConfig(s.configPath, s.cfg); err != nil {
		return err
	}
	if s.forward != nil {
		s.forward.Apply(CloneConfig(s.cfg))
	}
	return nil
}

func nodeExists(cfg *Config, nodeID string) bool {
	for _, node := range cfg.Socks5.Nodes {
		if node.ID == nodeID {
			return true
		}
	}
	return false
}

func nodeNameExists(cfg *Config, name string, excludeID string) bool {
	for _, node := range cfg.Socks5.Nodes {
		if node.Name == name && node.ID != excludeID {
			return true
		}
	}
	return false
}

func ruleNameExists(cfg *Config, name string, excludeID string) bool {
	for _, rule := range cfg.Forward.Rules {
		if rule.Name == name && rule.ID != excludeID {
			return true
		}
	}
	return false
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func redirectMsg(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/?msg="+url.QueryEscape(msg), http.StatusFound)
}

type pageData struct {
	Nodes      []Socks5Node
	Rules      []ForwardRule
	RuleErrors map[string]string
	Message    string
}

func renderLogin(w http.ResponseWriter, msg string) {
	tmpl := template.Must(template.New("login").Parse(loginTemplate))
	_ = tmpl.Execute(w, map[string]any{"Message": msg})
}

func renderIndex(w http.ResponseWriter, data pageData) {
	funcs := template.FuncMap{
		"eq": func(a, b string) bool { return a == b },
	}
	tmpl := template.Must(template.New("index").Funcs(funcs).Parse(indexTemplate))
	_ = tmpl.Execute(w, data)
}

const loginTemplate = `
<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>登录</title>
  <style>
    :root { --primary: #2563eb; --bg: #f3f4f6; --text: #1f2937; --white: #ffffff; --border: #e5e7eb; --danger: #ef4444; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: var(--bg); margin: 0; color: var(--text); display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; box-sizing: border-box; }
    .container { width: 100%; max-width: 400px; background: var(--white); padding: 32px; border-radius: 16px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); }
    h2 { margin-top: 0; text-align: center; color: #111827; margin-bottom: 24px; font-size: 24px; }
    .field { margin-bottom: 16px; }
    input { width: 100%; padding: 12px; border: 1px solid var(--border); border-radius: 8px; box-sizing: border-box; font-size: 16px; transition: border-color 0.2s; }
    input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1); }
    button { width: 100%; padding: 12px; border: none; background: var(--primary); color: var(--white); border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 500; transition: background 0.2s; }
    button:hover { background: #1d4ed8; }
    .msg { background: #fef2f2; color: var(--danger); padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; text-align: center; border: 1px solid #fee2e2; }
  </style>
</head>
<body>
  <div class="container">
    <h2>管理登录</h2>
    {{if .Message}}<div class="msg">{{.Message}}</div>{{end}}
    <form method="post" action="/login">
      <div class="field"><input name="password" type="password" placeholder="密码" required autocomplete="current-password"></div>
      <div class="field"><button type="submit">登录</button></div>
    </form>
  </div>
</body>
</html>
`

const indexTemplate = `
<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SocksForward</title>
  <style>
    :root { --primary: #2563eb; --primary-hover: #1d4ed8; --bg: #f3f4f6; --text: #1f2937; --text-light: #6b7280; --white: #ffffff; --border: #e5e7eb; --danger: #ef4444; --success: #10b981; }
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: var(--bg); margin: 0; color: var(--text); line-height: 1.5; padding-bottom: 40px; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    
    /* Topbar */
    .topbar { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; background: var(--white); padding: 16px 24px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 24px; gap: 12px; }
    .user-info { font-weight: 500; color: var(--text); display: flex; align-items: center; gap: 8px; }
    
    /* Cards */
    .card { background: var(--white); padding: 24px; border-radius: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 24px; overflow: hidden; }
    h3 { margin: 0; font-size: 18px; color: #111827; }
    h4 { margin: 24px 0 16px; font-size: 16px; color: #374151; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
    .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 8px; }
    .hint { font-size: 13px; color: var(--text-light); font-weight: normal; background: #f9fafb; padding: 4px 8px; border-radius: 4px; border: 1px solid var(--border); }

    /* Forms */
    input, select { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 14px; transition: border-color 0.2s, box-shadow 0.2s; background: #fff; }
    input:focus, select:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1); }
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 16px; }
    .form-row { display: flex; align-items: center; gap: 8px; }
    label { display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 14px; user-select: none; }
    input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--primary); margin: 0; }

    /* Buttons */
    button { height: 38px; padding: 0 16px; border: none; background: var(--primary); color: var(--white); border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 500; transition: all 0.2s; white-space: nowrap; display: inline-flex; align-items: center; justify-content: center; }
    button:hover { background: var(--primary-hover); }
    button:active { transform: translateY(1px); }
    .btn-secondary { background: #6b7280; }
    .btn-secondary:hover { background: #4b5563; }
    .btn-danger { background: var(--danger); }
    .btn-danger:hover { background: #dc2626; }
    .btn-success { background: var(--success); }
    .btn-success:hover { background: #059669; }
    .btn-sm { height: 32px; padding: 0 12px; font-size: 13px; }

    /* Actions Alignment */
    .actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .actions form { margin: 0; display: flex; }
    .actions input { height: 32px; padding: 0 10px; font-size: 13px; }
    
    /* Messages */
    .msg { background: #ecfdf5; color: #047857; padding: 12px 16px; border-radius: 12px; margin-bottom: 24px; border: 1px solid #a7f3d0; display: flex; align-items: center; }

    /* Modal */
    .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: none; justify-content: center; align-items: center; z-index: 1000; }
    .modal { background: #fff; padding: 24px; border-radius: 12px; width: 90%; max-width: 400px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04); animation: modalIn 0.2s ease-out; }
    .modal-title { font-size: 18px; font-weight: 600; margin-bottom: 8px; color: var(--text); }
    .modal-body { margin-bottom: 24px; color: #4b5563; font-size: 14px; line-height: 1.5; }
    .modal-actions { display: flex; justify-content: flex-end; gap: 12px; }
    @keyframes modalIn { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
    
    /* Responsive Tables */
    table { width: 100%; border-collapse: separate; border-spacing: 0; }
    th { text-align: left; padding: 12px 16px; background: #f9fafb; font-weight: 600; font-size: 13px; color: var(--text-light); text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }
    td { padding: 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
    
    /* Mobile styles */
    @media (max-width: 768px) {
      body { padding: 10px; padding-bottom: 80px; }
      .container { padding: 0; }
      .topbar { padding: 12px 16px; flex-direction: column; align-items: stretch; text-align: center; }
      .user-info { justify-content: center; margin-bottom: 8px; }
      .card { padding: 16px; border-radius: 12px; }
      
      /* Mobile Table -> Card View */
      table, thead, tbody, th, td, tr { display: block; }
      thead tr { position: absolute; top: -9999px; left: -9999px; }
      tr { margin-bottom: 16px; border: 1px solid var(--border); border-radius: 12px; background: #fff; box-shadow: 0 1px 2px rgba(0,0,0,0.05); overflow: hidden; }
      tr:last-child { margin-bottom: 0; }
      td { border: none; border-bottom: 1px solid #f3f4f6; position: relative; padding: 12px 16px; padding-left: 35%; display: flex; align-items: center; flex-wrap: wrap; min-height: 48px; }
      td:last-child { border-bottom: none; padding-left: 16px; justify-content: flex-end; background: #f9fafb; }
      
      /* Label for mobile */
      td::before { position: absolute; left: 16px; width: 30%; white-space: nowrap; font-weight: 600; font-size: 13px; color: var(--text-light); content: attr(data-label); }
      
      /* Inputs in table cells on mobile */
      td input, td select { width: 100%; }
      
      .form-grid { grid-template-columns: 1fr; }
      
      /* Hide "ID" inputs visually but keep them functional or use readonly style */
      input[readonly] { background: #f9fafb; color: #6b7280; border-color: transparent; padding-left: 0; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="topbar">
      <div class="user-info">
        <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
        SocksForward
      </div>
      <div class="actions">
        <button onclick="window.location.href = window.location.pathname" class="btn-success btn-sm">刷新</button>
        <form method="post" action="/logout" style="margin:0"><button type="submit" class="btn-secondary btn-sm">退出登录</button></form>
      </div>
    </div>
    
    {{if .Message}}
    <div class="msg">
      <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="margin-right: 8px;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
      {{.Message}}
    </div>
    {{end}}

    <div class="card">
      <div class="section-header">
        <h3>SOCKS5 节点</h3>
        <span class="hint">名称唯一，系统自动生成 ID</span>
      </div>
      
      {{if not .Nodes}}
      <div style="text-align:center; padding: 20px; color: var(--text-light);">暂无节点，请在下方添加</div>
      {{else}}
      <table>
        <thead>
          <tr>
            <th width="20%">名称</th>
            <th width="25%">地址</th>
            <th width="20%">用户名</th>
            <th width="20%">密码</th>
            <th width="15%">操作</th>
          </tr>
        </thead>
        <tbody>
          {{range .Nodes}}
          <tr>
            <form method="post" action="/nodes/update" style="margin:0">
              <td data-label="名称">
                <input type="hidden" name="id" value="{{.ID}}">
                <input name="name" value="{{.Name}}" required placeholder="名称">
              </td>
              <td data-label="地址"><input name="address" value="{{.Address}}" required placeholder="host:port"></td>
              <td data-label="用户名"><input name="username" value="{{.Username}}" placeholder="可选"></td>
              <td data-label="密码"><input name="password" type="password" value="{{.Password}}" placeholder="可选"></td>
              <td class="actions">
                <button type="submit" class="btn-sm" style="min-width: 60px">保存</button>
            </form>
                <form method="post" action="/nodes/delete" style="margin:0" onsubmit="confirmDelete(event, this)">
                  <input type="hidden" name="id" value="{{.ID}}">
                  <button type="submit" class="btn-danger btn-sm" style="min-width: 60px">删除</button>
                </form>
              </td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{end}}

      <h4>新增节点</h4>
      <form method="post" action="/nodes/add">
        <div class="form-grid">
          <div><label class="small-label">名称</label><input name="name" placeholder="节点名称" required></div>
          <div><label class="small-label">地址</label><input name="address" placeholder="127.0.0.1:1080" required></div>
          <div><label class="small-label">用户名</label><input name="username" placeholder="可选"></div>
          <div><label class="small-label">密码</label><input name="password" type="password" placeholder="可选"></div>
        </div>
        <div class="form-row" style="justify-content: flex-end;">
           <button type="submit">添加节点</button>
        </div>
      </form>
    </div>

    <div class="card">
      <div class="section-header">
        <h3>转发规则</h3>
        <span class="hint">名称唯一，必须选择出口节点</span>
      </div>

      {{if not .Rules}}
      <div style="text-align:center; padding: 20px; color: var(--text-light);">暂无规则，请在下方添加</div>
      {{else}}
      <table>
        <thead>
          <tr>
            <th width="15%">名称</th>
            <th width="10%">协议</th>
            <th width="20%">监听</th>
            <th width="20%">目标</th>
            <th width="15%">节点</th>
            <th width="20%">操作</th>
          </tr>
        </thead>
        <tbody>
          {{range .Rules}}
          {{$rule := .}}
          <tr>
            <form method="post" action="/rules/update" style="margin:0">
              <td data-label="名称">
                <input type="hidden" name="id" value="{{.ID}}">
                <input name="name" value="{{.Name}}" required placeholder="名称">
              </td>
              <td data-label="协议">
                <select name="proto">
                  <option value="tcp" {{if eq .Proto "tcp"}}selected{{end}}>TCP</option>
                  <option value="udp" {{if eq .Proto "udp"}}selected{{end}}>UDP</option>
                  <option value="both" {{if eq .Proto "both"}}selected{{end}}>Both</option>
                </select>
              </td>
              <td data-label="监听"><input name="listen" value="{{.Listen}}" required placeholder=":8080"></td>
              <td data-label="目标"><input name="target" value="{{.Target}}" required placeholder="host:port"></td>
              <td data-label="节点">
                <select name="socks5NodeId" required>
                  {{range $.Nodes}}
                  <option value="{{.ID}}" {{if eq .ID $rule.Socks5NodeID}}selected{{end}}>{{if .Name}}{{.Name}}{{else}}{{.ID}}{{end}}</option>
                  {{end}}
                </select>
              </td>
              <td class="actions">
                <button type="submit" class="btn-sm" style="min-width: 60px">保存</button>
            </form>
                <form method="post" action="/rules/toggle" style="margin:0">
                  <input type="hidden" name="id" value="{{.ID}}">
                  {{if .Enabled}}
                    {{if index $.RuleErrors .ID}}
                      <button type="submit" class="btn-sm btn-danger" style="min-width: 60px" title="{{index $.RuleErrors .ID}}">启动失败</button>
                    {{else}}
                      <button type="submit" class="btn-sm btn-success" style="min-width: 60px">已启用</button>
                    {{end}}
                  {{else}}
                    <button type="submit" class="btn-sm btn-secondary" style="min-width: 60px">已停用</button>
                  {{end}}
                </form>
                <form method="post" action="/rules/delete" style="margin:0" onsubmit="confirmDelete(event, this)">
                  <input type="hidden" name="id" value="{{.ID}}">
                  <button type="submit" class="btn-danger btn-sm" style="min-width: 60px">删除</button>
                </form>
              </td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{end}}

      <h4>新增规则</h4>
      <form method="post" action="/rules/add">
        <div class="form-grid">
          <div><label class="small-label">名称</label><input name="name" placeholder="规则名称" required></div>
          <div>
            <label class="small-label">协议</label>
            <select name="proto" required>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="both">TCP & UDP</option>
            </select>
          </div>
          <div><label class="small-label">监听地址</label><input name="listen" placeholder=":8443" required></div>
          <div><label class="small-label">目标地址</label><input name="target" placeholder="104.16.16.16:443" required></div>
          <div>
            <label class="small-label">出口节点</label>
            <select name="socks5NodeId" required>
              {{range .Nodes}}<option value="{{.ID}}">{{if .Name}}{{.Name}}{{else}}{{.ID}}{{end}}</option>{{end}}
            </select>
          </div>
        </div>
        <div class="form-row" style="justify-content: space-between;">
          <label><input type="checkbox" name="enabled" checked> 立即启用</label>
          <button type="submit">添加规则</button>
        </div>
      </form>
    </div>
  </div>

  <div class="modal-overlay" id="confirmModal">
    <div class="modal">
      <div class="modal-title">确认操作</div>
      <div class="modal-body" id="confirmMessage">确定要执行此操作吗？</div>
      <div class="modal-actions">
        <button class="btn-secondary" onclick="closeModal()">取消</button>
        <button class="btn-danger" id="confirmBtn">确定</button>
      </div>
    </div>
  </div>

  <script>
    let pendingForm = null;
    const modal = document.getElementById('confirmModal');
    const msgElem = document.getElementById('confirmMessage');
    const confirmBtn = document.getElementById('confirmBtn');

    function confirmDelete(e, form) {
      e.preventDefault();
      pendingForm = form;
      msgElem.textContent = '确定要删除吗？此操作无法撤销。';
      modal.style.display = 'flex';
    }

    function closeModal() {
      modal.style.display = 'none';
      pendingForm = null;
    }

    confirmBtn.onclick = function() {
      if (pendingForm) {
        pendingForm.submit();
      }
      closeModal();
    };
    
    // Close on outside click
    modal.onclick = function(e) {
      if (e.target === modal) closeModal();
    }

    // Scroll position preservation
    document.addEventListener("DOMContentLoaded", function() {
        var scrollPos = sessionStorage.getItem('scrollPos');
        if (scrollPos) {
            window.scrollTo(0, parseInt(scrollPos));
            sessionStorage.removeItem('scrollPos');
        }
    });

    window.addEventListener('beforeunload', function() {
        sessionStorage.setItem('scrollPos', window.scrollY);
    });
  </script>
</body>
</html>
`
