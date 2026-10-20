//go:build darwin

package netadmin

// exitStamp is empty: exit nodes run on Linux only.
func exitStamp(string) string { return "" }
