package service

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/xtls/xray-core/infra/conf"
)

// legacy mKCP header/seed carried in kcpSettings.
type legacyKCPMaskFields struct {
	Header *struct {
		Type string `json:"type"`
	} `json:"header"`
	Seed string `json:"seed"`
}

// xray header type -> mkcp-legacy header; "none"/"" means no mask.
var legacyHeaderToMkcp = map[string]string{
	"srtp":         "srtp",
	"utp":          "utp",
	"wechat-video": "wechat",
	"dtls":         "dtls",
	"wireguard":    "wireguard",
}

// wrap a payload as a mkcp-legacy mask.
func mkcpLegacyMask(payload any) (conf.Mask, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return conf.Mask{}, fmt.Errorf("marshal mkcp-legacy settings: %w", err)
	}
	raw := json.RawMessage(b)
	return conf.Mask{Type: "mkcp-legacy", Settings: &raw}, nil
}

// turn legacy header/seed into a finalmask udp mask chain (nil = plain mKCP).
// Preserve the pre-26.9 wire layout: the newer Finalmask manager reverses
// the configured chain before wrapping, so reverse our legacy translation too.
func buildLegacyKCPMasks(networkSettings []byte) (*conf.FinalMask, error) {
	if len(networkSettings) == 0 {
		return nil, nil
	}

	var fields legacyKCPMaskFields
	if err := json.Unmarshal(networkSettings, &fields); err != nil {
		return nil, fmt.Errorf("parse kcp legacy mask: %w", err)
	}

	var masks []conf.Mask

	if fields.Header != nil && fields.Header.Type != "" && fields.Header.Type != "none" {
		mapped, ok := legacyHeaderToMkcp[fields.Header.Type]
		if !ok {
			return nil, fmt.Errorf("unsupported mkcp header type %q", fields.Header.Type)
		}
		m, err := mkcpLegacyMask(struct {
			Header string `json:"header"`
		}{Header: mapped})
		if err != nil {
			return nil, err
		}
		masks = append(masks, m)
	}

	if fields.Seed != "" {
		m, err := mkcpLegacyMask(struct {
			Value string `json:"value"`
		}{Value: fields.Seed})
		if err != nil {
			return nil, err
		}
		masks = append(masks, m)
	}

	if len(masks) == 0 {
		return nil, nil
	}
	slices.Reverse(masks)
	return &conf.FinalMask{Udp: masks}, nil
}
