package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/spf13/cobra"
)

// パスワードをプロンプトする関数
func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(password), nil
}

// PGP鍵ペアを生成する関数
func generateKey(name, email, passphrase string) (string, error) {
	key, err := crypto.GenerateKey(name, email, passphrase, 2048)
	if err != nil {
		return "", err
	}

	// 鍵をロック
	lockedKey, err := key.Lock([]byte(passphrase))
	if err != nil {
		return "", err
	}

	armored, err := lockedKey.Armor()
	if err != nil {
		return "", err
	}
	return armored, nil
}

// PGP暗号化されたファイルを復号化する関数
func decryptPgpFile(encryptedFile string, privateKeyArmored string, passphrase string) (string, error) {
	encData, err := os.ReadFile(encryptedFile)
	if err != nil {
		return "", err
	}
	message, err := crypto.NewPGPMessageFromArmored(string(encData))
	if err != nil {
		return "", err
	}

	keyObj, err := crypto.NewKeyFromArmored(privateKeyArmored)
	if err != nil {
		return "", err
	}

	// IsLocked() のエラーチェックを追加
	isLocked, err := keyObj.IsLocked()
	if err != nil {
		return "", err
	}

	var unlockedKeyObj *crypto.Key
	if isLocked {
		unlockedKeyObj, err = keyObj.Unlock([]byte(passphrase))
		if err != nil {
			return "", err
		}
	} else {
		unlockedKeyObj = keyObj
	}

	keyRing, err := crypto.NewKeyRing(unlockedKeyObj)
	if err != nil {
		return "", err
	}
	decryptedData, err := keyRing.Decrypt(message, nil, 0)
	if err != nil {
		return "", err
	}
	return string(decryptedData.GetBinary()), nil
}

// PGP暗号化されたファイルを作成する関数
func encryptPgpFile(plaintext string, privateKeyArmored string, passphrase string, outputFile string) error {
	keyObj, err := crypto.NewKeyFromArmored(privateKeyArmored)
	if err != nil {
		return err
	}

	isLocked, err := keyObj.IsLocked()
	if err != nil {
		return err
	}

	var unlockedKeyObj *crypto.Key
	if isLocked {
		unlockedKeyObj, err = keyObj.Unlock([]byte(passphrase))
		if err != nil {
			return err
		}
	} else {
		unlockedKeyObj = keyObj
	}

	keyRing, err := crypto.NewKeyRing(unlockedKeyObj)
	if err != nil {
		return err
	}
	message := crypto.NewPlainMessage([]byte(plaintext))
	encryptedMessage, err := keyRing.Encrypt(message, nil)
	if err != nil {
		return err
	}
	encryptedArmored, err := encryptedMessage.GetArmored()
	if err != nil {
		return err
	}
	return ioutil.WriteFile(outputFile, []byte(encryptedArmored), 0644)
}

// `init` コマンドの実装
func initCmd(cmd *cobra.Command, args []string) {
	passphrase, err := promptPassword("Enter a passphrase for the new key: ")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	key, err := generateKey("User", "user@example.com", passphrase)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	err = ioutil.WriteFile("private.key", []byte(key), 0600)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Println("Key generated and saved to private.key")
}

// `edit` コマンドの実装
func editCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Please specify a secret file.")
		return
	}
	secretFile := args[0]
	privateKeyData, err := ioutil.ReadFile("private.key")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	passphrase, err := promptPassword("Enter passphrase for private key: ")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	var decryptedContent string
	if _, err := os.Stat(secretFile); os.IsNotExist(err) {
		fmt.Println("Secret file does not exist. Creating a new one.")
		decryptedContent = "" // 新しいファイルの場合、空の内容を設定
		// 空のコンテンツを暗号化して保存
		err = encryptPgpFile(decryptedContent, string(privateKeyData), passphrase, secretFile)
		if err != nil {
			fmt.Printf("Error creating new secret file: %v\n", err)
			return
		}
	} else {
		decryptedContent, err = decryptPgpFile(secretFile, string(privateKeyData), passphrase)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}

	tmpfile, err := ioutil.TempFile("", "secret")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(decryptedContent)); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if err := tmpfile.Close(); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	cmdEditor := exec.Command(editor, tmpfile.Name())
	cmdEditor.Stdin = os.Stdin
	cmdEditor.Stdout = os.Stdout
	cmdEditor.Stderr = os.Stderr
	err = cmdEditor.Run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	updatedContent, err := ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	err = encryptPgpFile(string(updatedContent), string(privateKeyData), passphrase, secretFile)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Println("Secret file updated.")
}

// `decode` コマンドの実装
func decodeCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Please specify a secret file to decode.")
		return
	}
	secretFile := args[0]
	privateKeyData, err := ioutil.ReadFile("private.key")
	if err != nil {
		fmt.Printf("Error reading private key: %v\n", err)
		return
	}
	passphrase, err := promptPassword("Enter passphrase for private key: ")
	if err != nil {
		fmt.Printf("Error reading passphrase: %v\n", err)
		return
	}

	decryptedContent, err := decryptPgpFile(secretFile, string(privateKeyData), passphrase)
	if err != nil {
		fmt.Printf("Error decoding file: %v\n", err)
		return
	}

	fmt.Println("Decoded content:")
	fmt.Println(decryptedContent)
}

// `env` コマンドの実装
func envCmd(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		fmt.Println("Please specify a secret file.")
		return
	}
	secretFile := args[0]
	privateKeyData, err := ioutil.ReadFile("private.key")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	passphrase, err := promptPassword("Enter passphrase for private key: ")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	decryptedContent, err := decryptPgpFile(secretFile, string(privateKeyData), passphrase)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// 環境変数を設定
	for _, line := range strings.Split(decryptedContent, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			fmt.Printf("# Invalid line: %s\n", line)
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		os.Setenv(key, value)
	}

	// 新しいシェルを起動
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	shellCmd := exec.Command(shell)
	shellCmd.Stdin = os.Stdin
	shellCmd.Stdout = os.Stdout
	shellCmd.Stderr = os.Stderr
	shellCmd.Env = os.Environ()

	err = shellCmd.Run()
	if err != nil {
		fmt.Printf("Error starting new shell: %v\n", err)
	}
}

func main() {
	var rootCmd = &cobra.Command{Use: "vlt"}
	var initCommand = &cobra.Command{
		Use:   "init",
		Short: "Initialize and generate a new key",
		Run:   initCmd,
	}
	var editCommand = &cobra.Command{
		Use:   "edit [secret_file]",
		Short: "Edit a secret file",
		Args:  cobra.MinimumNArgs(1),
		Run:   editCmd,
	}
	var decodeCommand = &cobra.Command{
		Use:   "decode [secret_file]",
		Short: "Decode and display the content of a secret file",
		Args:  cobra.ExactArgs(1),
		Run:   decodeCmd,
	}
	var envCommand = &cobra.Command{
		Use:   "env [secret_file]",
		Short: "Set environment variables from a secret file",
		Args:  cobra.MinimumNArgs(1),
		Run:   envCmd,
	}

	rootCmd.AddCommand(initCommand, editCommand, decodeCommand, envCommand)
	rootCmd.Execute()
}
