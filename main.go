package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"password-manager/crypto"
	"password-manager/storage"

	"github.com/google/uuid"
	"golang.org/x/term"
)

type PasswordManager struct {
	crypto  *crypto.CryptoManager
	storage *storage.Storage
}

func NewPasswordManager(masterPassword, filepath string) (*PasswordManager, error) {
	cm, err := crypto.NewCryptoManager(masterPassword)
	if err != nil {
		return nil, err
	}

	return &PasswordManager{
		crypto:  cm,
		storage: storage.NewStorage(filepath),
	}, nil
}

func readPasswordSecure() (string, error) {
	fmt.Print("введите мастер-пароль: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(password), nil
}

func (pm *PasswordManager) Initialize(masterPassword string) error {
	hash, salt, err := crypto.HashMasterPassword(masterPassword)
	if err != nil {
		return err
	}

	data := &storage.SafeData{
		MasterHash: hash,
		MasterSalt: salt,
		Passwords:  []storage.PasswordEntry{},
		Version:    1,
	}

	return pm.storage.Save(data)
}

func (pm *PasswordManager) AddPassword(note, password string) error {
	data, err := pm.storage.Load()
	if err != nil {
		return err
	}

	encrypted, err := pm.crypto.Encrypt(password)
	if err != nil {
		return err
	}

	encryptedJSON, err := json.Marshal(encrypted)
	if err != nil {
		return err
	}

	entry := storage.PasswordEntry{
		ID:        uuid.New().String(),
		Note:      note,
		Data:      string(encryptedJSON),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	data.Passwords = append(data.Passwords, entry)
	return pm.storage.Save(data)
}

func (pm *PasswordManager) ListPasswords() error {
	data, err := pm.storage.Load()
	if err != nil {
		return err
	}

	if len(data.Passwords) == 0 {
		fmt.Println("нет сохраненных паролей")
		return nil
	}

	fmt.Println("\nсохраненные пароли")
	for i, entry := range data.Passwords {
		fmt.Printf("%d. заметка: %s (ID: %s, создан: %s)\n",
			i+1, entry.Note, entry.ID[:8], entry.CreatedAt.Format("02.01.2006 15:04"))
	}
	return nil
}

func (pm *PasswordManager) GetPassword(id string) error {
	data, err := pm.storage.Load()
	if err != nil {
		return err
	}

	for _, entry := range data.Passwords {
		if strings.HasPrefix(entry.ID, id) {
			var encrypted crypto.EncryptedData
			if err := json.Unmarshal([]byte(entry.Data), &encrypted); err != nil {
				return err
			}

			password, err := pm.crypto.Decrypt(&encrypted)
			if err != nil {
				return err
			}

			fmt.Printf("\n пароль для заметки '%s' =\n", entry.Note)
			fmt.Printf("пароль: %s\n", password)
			fmt.Printf("создан: %s\n", entry.CreatedAt.Format("02.01.2006 15:04"))
			return nil
		}
	}

	return fmt.Errorf("пароль с ID %s не найден", id)
}

func (pm *PasswordManager) DeletePassword(id string) error {
	data, err := pm.storage.Load()
	if err != nil {
		return err
	}

	for i, entry := range data.Passwords {
		if strings.HasPrefix(entry.ID, id) {
			data.Passwords = append(data.Passwords[:i], data.Passwords[i+1:]...)
			return pm.storage.Save(data)
		}
	}

	return fmt.Errorf("пароль с ID %s не найден", id)
}

func main() {
	filepath := "passwords.safe"

	_, err := os.Stat(filepath)
	isNew := os.IsNotExist(err)

	masterPassword, err := readPasswordSecure()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка чтения пароля: %v\n", err)
		os.Exit(1)
	}

	pm, err := NewPasswordManager(masterPassword, filepath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка создания менеджера: %v\n", err)
		os.Exit(1)
	}

	if isNew {
		fmt.Println("создание нового хранилища...")
		if err := pm.Initialize(masterPassword); err != nil {
			fmt.Fprintf(os.Stderr, "ошибка инициализации: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("хранилище успешно создано!")
	} else {
		data, err := pm.storage.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ошибка загрузки: %v\n", err)
			os.Exit(1)
		}

		if !crypto.VerifyMasterPassword(masterPassword, data.MasterHash, data.MasterSalt) {
			fmt.Println("неверный мастер-пароль!")
			os.Exit(1)
		}
		fmt.Println("доступ разрешен!")
	}

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println("\nМенеджер паролей")
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
			fmt.Print("введите заметку для пароля: ")
			scanner.Scan()
			note := strings.TrimSpace(scanner.Text())

			fmt.Print("введите пароль для сохранения: ")
			passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				fmt.Fprintf(os.Stderr, "ошибка чтения: %v\n", err)
				continue
			}
			fmt.Println()
			password := string(passwordBytes)

			if password == "" {
				fmt.Println("пароль не может быть пустым")
				continue
			}

			if err := pm.AddPassword(note, password); err != nil {
				fmt.Fprintf(os.Stderr, "ошибка сохранения: %v\n", err)
				continue
			}

			for i := range passwordBytes {
				passwordBytes[i] = 0
			}

			fmt.Println("пароль успешно сохранен!")

		case "2":
			if err := pm.ListPasswords(); err != nil {
				fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
			}

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
				fmt.Println("пароль удален")
			}

		case "5":
			fmt.Println("до свидания")
			return

		default:
			fmt.Println("неверный выбор")
		}
	}
}
