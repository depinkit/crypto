// Copyright 2024, Nunet
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package crypto

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/afero"
)

func GetDirectorySize(fs afero.Fs, path string) (int64, error) {
	var size int64
	err := afero.Walk(fs, path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("failed to calculate volume size: %w", err)
	}

	return size, nil
}

// WriteToFile writes data to a file.
func WriteToFile(fs afero.Fs, data []byte, filePath string) (string, error) {
	if err := fs.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return "", fmt.Errorf("failed to open path: %w", err)
	}
	file, err := fs.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to create path: %w", err)
	}
	defer file.Close()
	n, err := file.Write(data)
	if err != nil {
		return "", fmt.Errorf("failed to write data to path: %w", err)
	}

	if n != len(data) {
		return "", errors.New("failed to write the size of data to file")
	}
	return filePath, nil
}

// FileExists checks if destination file exists
func FileExists(fs afero.Fs, filename string) bool {
	info, err := fs.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func CreateDirIfNotExists(fs afero.Afero, path string) error {
	if _, err := fs.Stat(path); os.IsNotExist(err) {
		err := fs.MkdirAll(path, 0o777) // Creates parent directories if needed
		if err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}
	return nil
}

// CurrentFileDirectory returns the path of this file
func CurrentFileDirectory() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Dir(file)
}
