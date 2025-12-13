package main

import (
	"testing"
)

func TestCleanLanguage(t *testing.T) {
	var foulString string
	type testCase struct {
		test     string
		expected string
	}

	cases := []testCase{
		{
			test:     "I am a kerfuffle",
			expected: "I am a ****",
		},
		{
			test:     "I am a sharbert",
			expected: "I am a ****",
		},
		{
			test:     "I am a fornax",
			expected: "I am a ****",
		},
	}

	for _, Case := range cases {
		foulString = Case.test
		cleanLanguage(&foulString)
		if foulString != Case.expected {
			t.Errorf("Expected: %s ; but was: %s", Case.expected, foulString)
		}
	}
}
