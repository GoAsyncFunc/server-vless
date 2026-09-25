package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

// maxPushResponseBytes bounds the heartbeat response we buffer. UniProxy applies
// the same limit to every other response (client.go:maxResponseBodyBytes), so
// mirroring it keeps the hand-rolled heartbeat from being the one endpoint whose
// reply we would read without a ceiling.
const maxPushResponseBytes = 8 * 1024 * 1024

// PanelClient keeps the validated UniProxy client and adds the empty /push
// heartbeat that api.Client deliberately treats as a no-op.
type PanelClient struct {
	*api.Client
	pushURL string
	http    *http.Client
}

func NewPanelClient(config *api.Config) (*PanelClient, error) {
	client, err := api.NewWithError(config)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(config.APIHost)
	if err != nil {
		return nil, fmt.Errorf("invalid panel URL")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/server/UniProxy/push"
	q := u.Query()
	q.Set("node_id", strconv.Itoa(config.NodeID))
	// Not api.Client.NodeType: that field is deprecated. server-vless is
	// vless-only -- node.go pins api.Vless, which is already the normalized
	// spelling -- so the value we validated is the one the client would report.
	q.Set("node_type", config.NodeType)
	q.Set("token", config.Key)
	u.RawQuery = q.Encode()
	// Clone the default transport to inherit its connection pooling and proxy
	// settings. The constructor already rejects a DefaultTransport it cannot
	// use, so this is redundant today; it stays because this function reads
	// the package-level variable a second time, and reporting an error beats
	// panicking if that read ever disagrees with the constructor's.
	defaultTransport := http.DefaultTransport
	baseTransport, ok := defaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("http.DefaultTransport is %T, not *http.Transport; cannot clone it for the panel client", defaultTransport)
	}
	transport := baseTransport.Clone()
	if config.APISendIP != "" {
		dialer := &net.Dialer{Timeout: 30 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(config.APISendIP)}}
		transport.DialContext = dialer.DialContext
	}
	timeout := time.Duration(config.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &PanelClient{Client: client, pushURL: u.String(), http: &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *PanelClient) ReportUserTraffic(ctx context.Context, traffic []api.UserTraffic) error {
	if len(traffic) > 0 {
		return c.Client.ReportUserTraffic(ctx, traffic)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.pushURL, bytes.NewBufferString("{}"))
	if err != nil {
		return fmt.Errorf("create empty traffic heartbeat")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("empty traffic heartbeat request failed")
	}
	defer response.Body.Close()
	return checkPushAcknowledgement(response)
}

// checkPushAcknowledgement mirrors api.Client.checkReportResponse, which every
// non-empty report goes through. The empty heartbeat has to be hand-rolled --
// api.Client.ReportUserTraffic returns early on an empty slice -- so without
// this it would be the one report where a 200 carrying {"data":false} still
// counted as success, and a panel that stopped accepting our traffic would look
// healthy from the node side.
//
// The error deliberately carries no URL and no response body: pushURL has the
// node token in its query string, and the caller only needs to know that the
// heartbeat was not acknowledged.
func checkPushAcknowledgement(response *http.Response) error {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("empty traffic heartbeat HTTP %d", response.StatusCode)
	}
	// 204 means accepted with no body, same as the non-empty path.
	if response.StatusCode == http.StatusNoContent {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPushResponseBytes))
	if err != nil {
		return fmt.Errorf("read empty traffic heartbeat response: %w", err)
	}
	var acknowledgement struct {
		Data *bool `json:"data"`
	}
	if err := json.Unmarshal(body, &acknowledgement); err != nil {
		return fmt.Errorf("decode empty traffic heartbeat acknowledgement: %w", err)
	}
	if acknowledgement.Data == nil {
		return fmt.Errorf("empty traffic heartbeat response must include a boolean data acknowledgement")
	}
	if !*acknowledgement.Data {
		return fmt.Errorf("empty traffic heartbeat was not acknowledged")
	}
	return nil
}

// PanelAPI allows lifecycle tests to inject failures without changing wire contracts.
type PanelAPI interface {
	GetNodeInfo(context.Context) (*api.NodeInfo, error)
	GetUserList(context.Context) ([]api.UserInfo, error)
	ReportUserTraffic(context.Context, []api.UserTraffic) error
	ReportNodeOnlineUsers(context.Context, map[int][]netip.Addr) error
	GetAliveList(context.Context) (map[int]int, error)
}
