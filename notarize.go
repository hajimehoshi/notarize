// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2024 Hajime Hoshi

// Package notarize provides APIs for Apple application notarization.
package notarize

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

const entitlementsPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key>
    <true/>
  </dict>
</plist>`

// NotarizeOptions represents options for Notarize.
type NotarizeOptions struct {
	// Email is the email address for the Apple ID.
	Email string

	// DeveloperName is the developer name.
	DeveloperName string

	// TeamID is the team ID.
	TeamID string

	// AppPassword is the app-specific password.
	// See https://support.apple.com/en-us/102654 for details.
	AppPassword string

	// ProgressOutput is the output for progress.
	// If ProgressOutput is nil, the output is discarded.
	ProgressOutput io.Writer
}

// Notarize notarizes the app at appPath using the given options.
// appPath is the file path to .app directory.
func Notarize(appPath string, options *NotarizeOptions) error {
	tmp, err := os.MkdirTemp("", "")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	entitlements := filepath.Join(tmp, "entitlements.plist")
	if err := os.WriteFile(entitlements, []byte(entitlementsPlist), 0644); err != nil {
		return err
	}

	// Run codesign.
	{
		cmd := exec.Command("codesign",
			"--display",
			"--verbose",
			"--verify",
			"--sign", options.DeveloperName,
			"--timestamp",
			"--options", "runtime",
			"--force",
			"--entitlements", entitlements,
			"--deep",
			appPath)
		var buf bytes.Buffer
		cmd.Stderr = &buf
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("notarize: codesign failed: %w: %s", err, buf.String())
		}
	}

	// Run ditto to create a zip file.
	base := filepath.Base(appPath)
	zipname := base[:len(base)-len(filepath.Ext(base))] + ".zip"
	zippath := filepath.Join(tmp, zipname)
	{
		cmd := exec.Command("ditto", "-c", "-k", "--keepParent", appPath, zippath)
		var buf bytes.Buffer
		cmd.Stderr = &buf
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("notarize: ditto failed: %w: %s", err, buf.String())
		}
	}

	// Notarize the app.
	{
		cmd := exec.Command("xcrun", "notarytool", "submit", zippath,
			"--apple-id", options.Email,
			"--password", options.AppPassword,
			"--team-id", options.TeamID,
			"--wait")
		var buf bytes.Buffer
		cmd.Stdout = options.ProgressOutput
		cmd.Stderr = &buf
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("notarize: xcrun notarytool failed: %w: %s", err, buf.String())
		}
	}

	// Run stapler.
	{
		cmd := exec.Command("xcrun", "stapler", "staple", appPath)
		var buf bytes.Buffer
		cmd.Stdout = options.ProgressOutput
		cmd.Stderr = &buf
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("notarize: xcrun stapler failed: %w: %s", err, buf.String())
		}
	}

	return nil
}
