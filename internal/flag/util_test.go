package flag

import "testing"

func TestIsHTTPURL(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{
			input:    "http://example.com",
			expected: true,
		},
		{
			input:    "https://example.com",
			expected: true,
		},
		{
			input:    "/home/user/file.txt",
			expected: false,
		},
		{
			input:    "oci://ghcr.io/user/file",
			expected: false,
		},
	}

	for _, testCase := range testCases {
		if actual := IsHTTPURL(testCase.input); actual != testCase.expected {
			t.Errorf("isHTTPURL(%v) = %v; expected %v", testCase.input, actual, testCase.expected)
		}
	}
}

func TestOneOf(t *testing.T) {
	testCases := []struct {
		image     string
		repo      string
		imageFile string
		expected  bool
	}{
		{
			image:    "a",
			expected: true,
		},
		{
			repo:     "b",
			expected: true,
		},
		{
			imageFile: "c",
			expected:  true,
		},
		{
			image:     "a",
			repo:      "b",
			imageFile: "c",
			expected:  false,
		},
		{
			image:    "a",
			repo:     "b",
			expected: false,
		},
		{
			repo:      "b",
			imageFile: "c",
			expected:  false,
		},
		{
			image:     "a",
			imageFile: "c",
			expected:  false,
		},
		{
			expected: false,
		},
	}

	for _, testCase := range testCases {
		if actual := OneOf(testCase.image, testCase.repo, testCase.imageFile); actual != testCase.expected {
			t.Errorf("onlyOne(%s,%s,%s) = %v; expected %v",
				testCase.image,
				testCase.repo,
				testCase.imageFile,
				actual,
				testCase.expected)
		}
	}
}
