package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/chzyer/readline"
)

const apiBaseURL = "http://localhost:8080/api/v1"

type CommandHandler func(context.Context, []string) error

type Command struct {
	Name        string
	Description string
	Handler     CommandHandler
}

type CLI struct {
	commands  map[string]Command
	client    *http.Client
	sessionID string
}

func New() *CLI {
	return &CLI{
		commands: make(map[string]Command),
		client:   &http.Client{},
	}
}

func (c *CLI) RegisterCommand(command Command) {
	c.commands[command.Name] = command
}

func (c *CLI) Run(ctx context.Context) error {
	completer := readline.NewPrefixCompleter(
		readline.PcItem("help"),
		readline.PcItem("register"),
		readline.PcItem("login"),
		readline.PcItem("whoami"),
		readline.PcItem("enable-2fa"),
		readline.PcItem("disable-2fa"),
		readline.PcItem("logout"),
		readline.PcItem("exit"),
	)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "auth> ",
		HistoryFile:     ".auth_history",
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return fmt.Errorf("initialize CLI: %w", err)
	}
	defer rl.Close()

	fmt.Println("Go CLI Auth")
	fmt.Println("Type 'help' for available commands.")
	fmt.Println()

	for {
		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				continue
			}
			if err == io.EOF {
				fmt.Println()
				return nil
			}
			return fmt.Errorf("read command: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		args := strings.Fields(line)
		commandName := args[0]

		if commandName == "exit" {
			fmt.Println("Goodbye!")
			return nil
		}

		command, ok := c.commands[commandName]
		if !ok {
			fmt.Printf("unknown command: %s\n", commandName)
			fmt.Println("Type 'help' to see available commands.")
			continue
		}

		if err := command.Handler(ctx, args[1:]); err != nil {
			fmt.Printf("error: %v\n", err)
		}
	}
}

type apiError struct {
	Error string `json:"error"`
}

func (c *CLI) request(
	ctx context.Context,
	method string,
	path string,
	body any,
	result any,
	authenticated bool,
) error {
	var bodyReader io.Reader

	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		method,
		apiBaseURL+path,
		bodyReader,
	)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if authenticated {
		if c.sessionID == "" {
			return fmt.Errorf("not logged in")
		}

		req.Header.Set("Authorization", "Bearer "+c.sessionID)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr apiError

		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil &&
			apiErr.Error != "" {
			return fmt.Errorf("%s", apiErr.Error)
		}

		return fmt.Errorf("request failed with status %s", resp.Status)
	}

	if result == nil {
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

func (c *CLI) Register(ctx context.Context, args []string) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	fmt.Print("Password: ")
	password, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	var result struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	}

	err = c.request(
		ctx,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"username": strings.TrimSpace(username),
			"password": strings.TrimSpace(password),
		},
		&result,
		false,
	)
	if err != nil {
		return err
	}

	fmt.Printf("Account created successfully. User ID: %d\n", result.ID)
	return nil
}

func (c *CLI) Login(ctx context.Context, args []string) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	fmt.Print("Password: ")
	password, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	fmt.Print("TOTP code (press Enter if disabled): ")
	totpCode, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	var result struct {
		SessionID string `json:"session_id"`
		ExpiresAt string `json:"expires_at"`
	}

	err = c.request(
		ctx,
		http.MethodPost,
		"/auth/login",
		map[string]string{
			"username":  strings.TrimSpace(username),
			"password":  strings.TrimSpace(password),
			"totp_code": strings.TrimSpace(totpCode),
		},
		&result,
		false,
	)
	if err != nil {
		return err
	}

	c.sessionID = result.SessionID

	fmt.Println("Login successful.")
	fmt.Printf("Session expires at: %s\n", result.ExpiresAt)

	return nil
}

func (c *CLI) Whoami(ctx context.Context, args []string) error {
	var result struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	}

	if err := c.request(
		ctx,
		http.MethodGet,
		"/me",
		nil,
		&result,
		true,
	); err != nil {
		return err
	}

	fmt.Printf("ID: %d\nUsername: %s\n", result.ID, result.Username)
	return nil
}

func (c *CLI) EnableMFA(ctx context.Context, args []string) error {
	var result struct {
		Secret string `json:"secret"`
		URL    string `json:"url"`
	}

	if err := c.request(
		ctx,
		http.MethodPost,
		"/auth/mfa/setup",
		nil,
		&result,
		true,
	); err != nil {
		return err
	}

	fmt.Println("2FA setup generated.")
	fmt.Printf("Secret: %s\n", result.Secret)
	fmt.Printf("Authenticator URL: %s\n", result.URL)

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the 6-digit code from your authenticator app: ")
	code, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	var verifyResult struct {
		MFAEnabled bool `json:"mfa_enabled"`
	}

	if err := c.request(
		ctx,
		http.MethodPost,
		"/auth/mfa/verify",
		map[string]string{
			"code": strings.TrimSpace(code),
		},
		&verifyResult,
		true,
	); err != nil {
		return err
	}

	if !verifyResult.MFAEnabled {
		return fmt.Errorf("MFA verification did not enable 2FA")
	}

	fmt.Println("Two-factor authentication enabled successfully.")
	return nil
}

func (c *CLI) DisableMFA(ctx context.Context, args []string) error {
	if err := c.request(
		ctx,
		http.MethodPost,
		"/auth/mfa/disable",
		nil,
		nil,
		true,
	); err != nil {
		return err
	}

	fmt.Println("Two-factor authentication disabled.")
	return nil
}

func (c *CLI) Logout(ctx context.Context, args []string) error {
	if err := c.request(
		ctx,
		http.MethodPost,
		"/auth/logout",
		nil,
		nil,
		true,
	); err != nil {
		return err
	}

	c.sessionID = ""
	fmt.Println("Logged out successfully.")
	return nil
}

func (c *CLI) RegisterBuiltInCommands() {
	c.RegisterCommand(Command{
		Name:        "register",
		Description: "Create a new account",
		Handler:     c.Register,
	})

	c.RegisterCommand(Command{
		Name:        "login",
		Description: "Login to your account",
		Handler:     c.Login,
	})

	c.RegisterCommand(Command{
		Name:        "whoami",
		Description: "Show current user",
		Handler:     c.Whoami,
	})

	c.RegisterCommand(Command{
		Name:        "enable-2fa",
		Description: "Enable two-factor authentication",
		Handler:     c.EnableMFA,
	})

	c.RegisterCommand(Command{
		Name:        "disable-2fa",
		Description: "Disable two-factor authentication",
		Handler:     c.DisableMFA,
	})

	c.RegisterCommand(Command{
		Name:        "logout",
		Description: "Logout",
		Handler:     c.Logout,
	})
}
