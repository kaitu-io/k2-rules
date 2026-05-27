package krs

import "testing"

// matchGlob is the single-* glob primitive used by all app-pattern matchers.
// The same impl serves Android/Windows/Darwin — case folding happens at
// the caller (Windows lowercases both pattern and query).
func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, input string
		want           bool
	}{
		// Exact match (no wildcards).
		{"WeChat", "WeChat", true},
		{"WeChat", "WeChatHelper", false},
		{"WeChat", "wechat", false}, // case-sensitive
		{"", "", true},
		{"", "anything", false},

		// Prefix glob.
		{"WeChat*", "WeChat", true},
		{"WeChat*", "WeChatHelper", true},
		{"WeChat*", "WeChat.exe", true},
		{"WeChat*", "weChat", false}, // case-sensitive
		{"WeChat*", "AWeChat", false},

		// Suffix glob.
		{"*chat", "chat", true},
		{"*chat", "WeChat", false}, // case-sensitive
		{"*chat", "wechat", true},
		{"*chat", "chats", false},  // must end with literal
		{"*chat", "chatter", false},

		// Contains glob.
		{"*chat*", "chat", true},
		{"*chat*", "wechat", true},
		{"*chat*", "chatter", true},
		{"*chat*", "abc.chat.xyz", true},
		{"*chat*", "Chat", false}, // case-sensitive

		// Middle wildcard.
		{"Wei*Chat", "WeiChat", true},
		{"Wei*Chat", "WeiXinChat", true},
		{"Wei*Chat", "WeChat", false}, // missing "Wei" prefix
		{"Wei*Chat", "WeiChats", false},

		// Single star matches anything.
		{"*", "", true},
		{"*", "anything", true},

		// Consecutive stars collapse semantically.
		{"**", "anything", true},
		{"a**b", "ab", true},
		{"a**b", "axyzb", true},

		// Pattern with only star at boundaries against empty.
		{"a*", "a", true},
		{"a*", "", false},
		{"*a", "a", true},
		{"*a", "", false},

		// Multi-wildcard with two non-empty middle segments. The middle
		// matcher walks forward non-overlappingly — earlier hit must not
		// consume bytes the next segment needs.
		{"*foo*bar*", "foobar", true},
		{"*foo*bar*", "xfooybarz", true},
		{"*foo*bar*", "barfoo", false},     // wrong order
		{"*foo*bar*", "foo", false},        // missing "bar"
		{"*foo*bar*", "foobarfoo", true},   // surplus chars OK
		{"a*b*c", "abc", true},
		{"a*b*c", "axxxbyyyc", true},
		{"a*b*c", "axxxc", false},          // missing "b"
		{"a*b*c", "abcb", false},           // "c" must anchor the tail

		// Greedy fallback regression: pattern "a*a*a" against "aaa".
		// Naive left-to-right matching could consume both "a"s for the
		// first segment and fail. The middle walker treats segments
		// as forward-only, so this remains correct.
		{"a*a*a", "aaa", true},
		{"a*a*a", "aa", false},
	}
	for _, tc := range cases {
		if got := matchGlob(tc.pattern, tc.input); got != tc.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.pattern, tc.input, got, tc.want)
		}
	}
}
