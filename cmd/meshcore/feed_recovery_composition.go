package main

import "time"

const (
	feedReconnectInitial = 100 * time.Millisecond
	feedReconnectMaximum = 5 * time.Second
)
