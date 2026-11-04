package main

import "testing"

func TestNormalizeCheckURI(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"/eUrbanUMA/main.htm", "/eUrbanUMA/main.htm"},
		{"http://172.21.133.222:8082/eUrbanUMA/main.htm", "/eUrbanUMA/main.htm"},
		{"http://127.0.0.1:8085/eUrbanGIS/main.htm?x=1", "/eUrbanGIS/main.htm?x=1"},
		{"127.0.0.1:8085/eUrbanUMA/main.htm", "/eUrbanUMA/main.htm"},
		{"172.21.133.221/main.htm", "/main.htm"},
		{"main.htm", "/main.htm"},
	}
	for _, c := range cases {
		if got := normalizeCheckURI(c.in); got != c.want {
			t.Fatalf("normalizeCheckURI(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
