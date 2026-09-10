package limiter

import "sync"

// Device counts are unique source IPs, not connections. Panel counts are an
// eventually consistent global snapshot (its API has no atomic reservation).
var devices = struct {
	sync.Mutex
	users map[string]*deviceState
}{users: make(map[string]*deviceState)}

type deviceState struct {
	limit    int
	remote   int
	ips      map[string]int
	reported map[string]bool
}

func SetDeviceLimit(email string, limit int) {
	devices.Lock()
	defer devices.Unlock()
	d := devices.users[email]
	if d == nil {
		d = &deviceState{ips: make(map[string]int), reported: make(map[string]bool)}
		devices.users[email] = d
	}
	d.limit = limit
}

// SyncDevices subtracts only local IPs that were present in the last successful
// alive report. New local connections must not be subtracted from remote usage.
func SyncDevices(email string, total int, reported []string) {
	devices.Lock()
	defer devices.Unlock()
	d := devices.users[email]
	if d == nil {
		return
	}
	d.reported = make(map[string]bool)
	for _, ip := range reported {
		d.reported[ip] = true
	}
	d.remote = max(0, total-len(d.reported))
}

func RemoveDevices(email string) { devices.Lock(); delete(devices.users, email); devices.Unlock() }

func AcquireDevice(email, ip string) (func(), bool) {
	devices.Lock()
	d := devices.users[email]
	if d == nil {
		devices.Unlock()
		return func() {}, true
	}
	if d.limit > 0 && d.ips[ip] == 0 && d.remote+len(d.ips) >= d.limit {
		devices.Unlock()
		return nil, false
	}
	d.ips[ip]++
	devices.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			devices.Lock()
			defer devices.Unlock()
			d.ips[ip]--
			if d.ips[ip] <= 0 {
				delete(d.ips, ip)
			}
		})
	}, true
}
