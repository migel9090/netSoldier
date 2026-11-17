module github.com/migel9090/netSoldier/apps/threat-intel-sync

go 1.27.4

require (
	github.com/migel9090/netSoldier/libs/events v0.0.0
	github.com/migel9090/netSoldier/libs/indicator v0.0.0
	github.com/prometheus/client_golang v1.24.1
	modernc.org/sqlite v1.51.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.20.4 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	modernc.org/libc v1.76.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

replace github.com/migel9090/netSoldier/libs/events v0.0.0 => ../../libs/events

replace github.com/migel9090/netSoldier/libs/indicator v0.0.0 => ../../libs/indicator
