module github.com/ostap-mykhaylyak/smoker

// Go 1.24+ is required so TLS servers offer the post-quantum X25519MLKEM768
// hybrid key exchange by default (CurvePreferences left nil).
go 1.25.0

require (
	github.com/fsnotify/fsnotify v1.7.0
	github.com/google/nftables v0.2.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/klauspost/compress v1.17.11
	github.com/quic-go/quic-go v0.60.0
	go.etcd.io/bbolt v1.3.11
	golang.org/x/crypto v0.51.0
	golang.org/x/sys v0.45.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)
