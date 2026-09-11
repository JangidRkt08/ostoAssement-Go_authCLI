package security

import "testing"

func TestHashPassword(t *testing.T) {
	password := "correct-horse-battery-staple"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hash == password {
		t.Fatal("password hash not equal plaintext password")
	}

	if !CheckPassword(password, hash) {
		t.Fatal("CheckPassword() rejected the correct password")
	}

	if CheckPassword("wrong-password", hash) {
		t.Fatal("CheckPassword() accepted an incorrect password")
	}
}
