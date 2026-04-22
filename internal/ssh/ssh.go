package ssh

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Client struct {
	Host     string
	Port     int
	Username string
	Password string
	client   *ssh.Client
	session  *ssh.Session
}

func NewClient(host string, port int, username, password string) *Client {
	return &Client{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
	}
}

func (c *Client) Connect() error {
	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	if c.Port == 0 {
		addr = c.Host
	}

	config := &ssh.ClientConfig{
		User: c.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to dial SSH: %w", err)
	}
	c.client = conn

	return nil
}

func (c *Client) Execute(command string) (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	session.Stdout = &bytes.Buffer{}
	session.Stderr = &bytes.Buffer{}

	if err := session.Run(command); err != nil {
		return "", fmt.Errorf("failed to run command %q: %w", command, err)
	}

	return session.Stdout.(*bytes.Buffer).String(), nil
}

func (c *Client) ExecuteWithPty(command string, timeout time.Duration) (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	session.Stdout = &bytes.Buffer{}
	session.Stderr = &bytes.Buffer{}

	if err := session.RequestPty("xterm", 80, 24, ssh.TerminalModes{}); err != nil {
		return "", fmt.Errorf("failed to request pty: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	select {
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("command failed: %w", err)
		}
		return session.Stdout.(*bytes.Buffer).String(), nil
	case <-time.After(timeout):
		session.Close()
		return "", fmt.Errorf("command timed out after %v", timeout)
	}
}

func (c *Client) ExecuteMultiple(commands []string) ([]string, error) {
	if c.client == nil {
		return nil, fmt.Errorf("not connected")
	}

	results := make([]string, 0, len(commands))
	for _, cmd := range commands {
		output, err := c.Execute(cmd)
		if err != nil {
			results = append(results, fmt.Sprintf("ERROR: %v", err))
		} else {
			results = append(results, output)
		}
	}
	return results, nil
}

func (c *Client) Close() error {
	if c.session != nil {
		c.session.Close()
	}
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

func (c *Client) IsConnected() bool {
	if c.client == nil {
		return false
	}
	_, _, err := c.client.SendRequest("keepalive@openssh.com", false, nil)
	return err == nil
}

func Connect(host string, port int, username, password string) (*Client, error) {
	c := NewClient(host, port, username, password)
	if err := c.Connect(); err != nil {
		return nil, err
	}
	return c, nil
}

type FortiGateClient struct {
	*Client
	timeout time.Duration
}

func NewFortiGateClient(host string, port int, username, password string) *FortiGateClient {
	if port == 0 {
		port = 22
	}
	return &FortiGateClient{
		Client:  NewClient(host, port, username, password),
		timeout: 60 * time.Second,
	}
}

func (c *FortiGateClient) Connect() error {
	return c.Client.Connect()
}

func (c *FortiGateClient) GetConfig() (string, error) {
	return c.ExecuteWithPty("show", c.timeout)
}

func (c *FortiGateClient) GetConfigChecksum() (string, error) {
	output, err := c.Execute("diagnose sys checksum conf")
	if err != nil {
		return "", err
	}
	output = strings.TrimSpace(output)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	return output, nil
}

func (c *FortiGateClient) GetSystemStatus() (string, error) {
	return c.Execute("get system status")
}

func (c *FortiGateClient) GetSystemPerformance() (string, error) {
	return c.Execute("get system performance status")
}

func (c *FortiGateClient) GetProcessTop() (string, error) {
	return c.ExecuteWithPty("diagnose sys top", c.timeout)
}

func (c *FortiGateClient) GetInterfaceList() (string, error) {
	return c.Execute("diagnose netlink interface list")
}

func (c *FortiGateClient) ExecuteFortiOSCmd(cmd string) (string, error) {
	return c.ExecuteWithPty(cmd, c.timeout)
}

func (c *FortiGateClient) Close() error {
	return c.Client.Close()
}

func ConnectFortiGate(host string, port int, username, password string) (*FortiGateClient, error) {
	c := NewFortiGateClient(host, port, username, password)
	if err := c.Connect(); err != nil {
		return nil, err
	}
	return c, nil
}

type TCPClient struct {
	Host     string
	Port     int
	Username string
	Password string
	conn     net.Conn
	client   *ssh.Client
}

func NewTCPClient(host string, port int, username, password string) *TCPClient {
	return &TCPClient{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
	}
}

func (c *TCPClient) Connect() error {
	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)

	config := &ssh.ClientConfig{
		User: c.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to dial SSH: %w", err)
	}
	c.client = conn

	return nil
}

func (c *TCPClient) OpenSession() (*ssh.Session, error) {
	if c.client == nil {
		return nil, fmt.Errorf("not connected")
	}
	return c.client.NewSession()
}

func (c *TCPClient) ReadOutput(reader io.Reader) string {
	buf := new(bytes.Buffer)
	io.Copy(buf, reader)
	return buf.String()
}

func (c *TCPClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}
