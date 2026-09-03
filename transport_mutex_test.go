package main

import (
	"strings"
	"testing"
)

// TestValidateClientTransport 校验客户端传输互斥逻辑：
// h3 / wt / masque / grpc 只能开一个；全关（默认 h2）或仅开一个视为合法。
func TestValidateClientTransport(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		want string // 空串=无冲突；否则期望错误信息中包含该子串
	}{
		{
			name: "默认全关（走 h2）合法",
			cfg:  &Config{},
			want: "",
		},
		{
			name: "仅 h3 合法",
			cfg:  &Config{H3: true},
			want: "",
		},
		{
			name: "仅 wt 合法",
			cfg:  &Config{WT: true},
			want: "",
		},
		{
			name: "仅 masque 合法",
			cfg:  &Config{Masque: true},
			want: "",
		},
		{
			name: "仅 grpc 合法",
			cfg:  &Config{GRPC: true},
			want: "",
		},
		{
			name: "h3 + wt 互斥报错",
			cfg:  &Config{H3: true, WT: true},
			want: "h3 + wt",
		},
		{
			name: "masque + grpc 互斥报错",
			cfg:  &Config{Masque: true, GRPC: true},
			want: "masque + grpc",
		},
		{
			name: "四开全报错",
			cfg:  &Config{H3: true, WT: true, Masque: true, GRPC: true},
			want: "h3 + wt + masque + grpc",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateClientTransport(tc.cfg)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("validateClientTransport(%+v) 应无冲突，实际报错: %q", tc.cfg, got)
				}
				return
			}
			if got == "" {
				t.Fatalf("validateClientTransport(%+v) 应报互斥，实际无冲突", tc.cfg)
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("报错信息 %q 应包含 %q", got, tc.want)
			}
		})
	}
}
