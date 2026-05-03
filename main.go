package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"password-manager/crypto"

	"github.com/google/uuid"
)

//НАСТРОЙКИ

type Config struct {
	TelegramID string `json:"telegram_id"`
	SyncMode   string `json:"sync_mode"`
}

var config Config

func loadConfig() {
	data, err := os.ReadFile("config.json")
	if err == nil {
		json.Unmarshal(data, &config)
	}
}

func saveConfig() {
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile("config.json", data, 0600)
}

var botURL = "https://password-bot-1p96.onrender.com"

func chooseMode() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("Выберите режим работы")
	fmt.Println("1.☁️  Онлайн")
	fmt.Println("(синхронизация с ботом)")
	fmt.Println("2.💻 Офлайн")
	fmt.Println("(локальное хранение)")

	if config.SyncMode != "" {
		fmt.Printf("текущий режим: %s\n", config.SyncMode)
	}
	fmt.Print("ваш выбор (1 или 2, Enter = оставить): ")
	scanner.Scan()
	choice := strings.TrimSpace(scanner.Text())

	if choice == "1" {
		config.SyncMode = "online"
		if config.TelegramID == "" {
			fmt.Println("\n📱 настройка синхронизации с ботом @passwordmebot")
			fmt.Print("введите ваш Telegram ID (показывается в боте): ")
			scanner.Scan()
			config.TelegramID = strings.TrimSpace(scanner.Text())
		}
		fmt.Println("✅ включен онлайн-режим")
	} else if choice == "2" {
		config.SyncMode = "offline"
		fmt.Println("✅ включен офлайн-режим")
	} else if config.SyncMode == "" {
		config.SyncMode = "offline"
		fmt.Println("✅ выбран офлайн-режим по умолчанию")
	}

	saveConfig()
}

//СТРУКТУРЫ

type PasswordEntry struct {
	ID        string    `json:"id"`
	Note      string    `json:"note"`
	Data      string    `json:"data"`
	CreatedAt time.Time `json:"created_at"`
}

type SafeData struct {
	MasterHash string          `json:"master_hash"`
	MasterSalt string          `json:"master_salt"`
	Passwords  []PasswordEntry `json:"passwords"`
	Version    int             `json:"version"`
}

type PasswordManager struct {
	crypto   *crypto.CryptoManager
	storage  *SafeData
	config   Config
	filepath string
}

//ХРАНИЛИЩЕ

func (pm *PasswordManager) loadStorage() *SafeData {
	if pm.config.SyncMode == "online" {
		return pm.loadFromBot()
	}
	return pm.loadLocal()
}

func (pm *PasswordManager) saveStorage() {
	if pm.config.SyncMode == "online" {
		pm.saveToBot()
		fmt.Println("💾 данные отправлены боту")
	} else {
		pm.saveLocal()
	}
}

func (pm *PasswordManager) loadLocal() *SafeData {
	data, err := os.ReadFile(pm.filepath)
	if err != nil {
		return &SafeData{Passwords: []PasswordEntry{}, Version: 1}
	}
	var storage SafeData
	json.Unmarshal(data, &storage)
	return &storage
}

func (pm *PasswordManager) saveLocal() {
	data, _ := json.MarshalIndent(pm.storage, "", "  ")
	os.WriteFile(pm.filepath, data, 0600)
}

// ОБЩЕНИЕ С БОТОМ

func (pm *PasswordManager) loadFromBot() *SafeData {
	url := fmt.Sprintf("%s/api/load?id=%s", botURL, pm.config.TelegramID)

	for i := 0; i < 3; i++ {
		if i > 0 {
			fmt.Printf("повторная попытка %d...\n", i+1)
			time.Sleep(3 * time.Second)
		}

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(url)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		defer resp.Body.Close()

		data, _ := io.ReadAll(resp.Body)
		fmt.Printf("DEBUG: ответ от бота: %s\n", string(data[:min(100, len(data))]))

		var storage SafeData
		json.Unmarshal(data, &storage)
		if len(storage.MasterHash) > 0 {
			return &storage
		}
	}

	return &SafeData{Passwords: []PasswordEntry{}, Version: 1}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (pm *PasswordManager) saveToBot() {
	url := fmt.Sprintf("%s/api/save?id=%s", botURL, pm.config.TelegramID)
	data, _ := json.Marshal(pm.storage)

	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("⚠️ ошибка отправки боту:", err)
		return
	}
	defer resp.Body.Close()
}

func NewPasswordManager(masterPassword string) (*PasswordManager, error) {
	cm, err := crypto.NewCryptoManager(masterPassword)
	if err != nil {
		return nil, err
	}

	pm := &PasswordManager{
		crypto:   cm,
		config:   config,
		filepath: "passwords.safe",
	}

	// Загружаем ОДИН раз
	if config.SyncMode == "online" {
		pm.storage = pm.loadFromBot()
		if len(pm.storage.MasterHash) > 0 {
			fmt.Println("✅ аккаунт найден у бота")
		} else {
			fmt.Println("⚠️ у бота нет данных")
			pm.storage = &SafeData{Passwords: []PasswordEntry{}, Version: 1}
		}
	} else {
		pm.storage = pm.loadLocal()
	}

	return pm, nil
}

func (pm *PasswordManager) Initialize(masterPassword string) error {
	hash, salt, err := crypto.HashMasterPassword(masterPassword)
	if err != nil {
		return err
	}

	pm.storage = &SafeData{
		MasterHash: hash,
		MasterSalt: salt,
		Passwords:  []PasswordEntry{},
		Version:    1,
	}

	pm.saveStorage()
	return nil
}

func (pm *PasswordManager) AddPassword(note, password string) error {
	encrypted, err := pm.crypto.Encrypt(password)
	if err != nil {
		return err
	}

	encryptedJSON, err := json.Marshal(encrypted)
	if err != nil {
		return err
	}

	entry := PasswordEntry{
		ID:        uuid.New().String(),
		Note:      note,
		Data:      string(encryptedJSON),
		CreatedAt: time.Now(),
	}

	pm.storage.Passwords = append(pm.storage.Passwords, entry)
	pm.saveStorage()
	return nil
}

func (pm *PasswordManager) ListPasswords() error {
	if len(pm.storage.Passwords) == 0 {
		fmt.Println("нет сохраненных паролей")
		return nil
	}

	mode := "💻 офлайн"
	if pm.config.SyncMode == "online" {
		mode = "☁️ онлайн"
	}

	fmt.Printf("\nсохраненные пароли (%s):\n", mode)
	for i, entry := range pm.storage.Passwords {
		fmt.Printf("%d. заметка: %s (ID: %s, создан: %s)\n",
			i+1, entry.Note, entry.ID[:8], entry.CreatedAt.Format("02.01.2006 15:04"))
	}
	return nil
}

func (pm *PasswordManager) GetPassword(id string) error {
	for _, entry := range pm.storage.Passwords {
		if strings.HasPrefix(entry.ID, id) {
			var encrypted crypto.EncryptedData
			if err := json.Unmarshal([]byte(entry.Data), &encrypted); err != nil {
				return err
			}

			password, err := pm.crypto.Decrypt(&encrypted)
			if err != nil {
				return err
			}

			fmt.Printf("\nпароль для заметки '%s':\n", entry.Note)
			fmt.Printf("пароль: %s\n", password)
			return nil
		}
	}
	return fmt.Errorf("пароль с ID %s не найден", id)
}

func (pm *PasswordManager) DeletePassword(id string) error {
	for i, entry := range pm.storage.Passwords {
		if strings.HasPrefix(entry.ID, id) {
			pm.storage.Passwords = append(pm.storage.Passwords[:i], pm.storage.Passwords[i+1:]...)
			pm.saveStorage()
			return nil
		}
	}
	return fmt.Errorf("пароль с ID %s не найден", id)
}

func readPasswordSecure() (string, error) {
	fmt.Print("введите мастер-пароль: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text(), scanner.Err()
}

//MAIN

func main() {
	loadConfig()
	chooseMode()

	if config.SyncMode == "online" && config.TelegramID != "" {
		fmt.Println("🔄 синхронизация с ботом...")
	}

	masterPassword, err := readPasswordSecure()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка чтения пароля: %v\n", err)
		os.Exit(1)
	}

	pm, err := NewPasswordManager(masterPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		os.Exit(1)
	}

	if len(pm.storage.MasterHash) == 0 {
		fmt.Println("создание нового аккаунта...")
		if err := pm.Initialize(masterPassword); err != nil {
			fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ аккаунт создан!")
	} else {
		if !crypto.VerifyMasterPassword(masterPassword, pm.storage.MasterHash, pm.storage.MasterSalt) {
			fmt.Println("неверный мастер-пароль")
			os.Exit(1)
		}
		fmt.Println("✅ доступ разрешен")
	}

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println("\nменеджер паролей")
		fmt.Println("1. добавить пароль")
		fmt.Println("2. показать все заметки")
		fmt.Println("3. получить пароль")
		fmt.Println("4. удалить пароль")
		fmt.Println("5. выход")
		fmt.Print("выберите действие: ")

		scanner.Scan()
		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			fmt.Print("введите заметку: ")
			scanner.Scan()
			note := strings.TrimSpace(scanner.Text())

			fmt.Print("введите пароль: ")
			scanner.Scan()
			password := strings.TrimSpace(scanner.Text())

			if password == "" {
				fmt.Println("пароль не может быть пустым")
				continue
			}

			if err := pm.AddPassword(note, password); err != nil {
				fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
			} else {
				fmt.Println("✅ пароль сохранен!")
			}
		case "2":
			pm.ListPasswords()

		case "3":
			fmt.Print("введите ID пароля: ")
			scanner.Scan()
			id := strings.TrimSpace(scanner.Text())
			if err := pm.GetPassword(id); err != nil {
				fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
			}

		case "4":
			fmt.Print("введите ID пароля для удаления: ")
			scanner.Scan()
			id := strings.TrimSpace(scanner.Text())
			if err := pm.DeletePassword(id); err != nil {
				fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
			} else {
				fmt.Println("✅ пароль удален")
			}

		case "5":
			fmt.Println("до свидания")
			return

		default:
			fmt.Println("неверный выбор")
		}
	}
}
