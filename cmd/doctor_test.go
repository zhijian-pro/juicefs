/*
 * JuiceFS, Copyright 2022 Juicedata, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDoctor(t *testing.T) {
	Convey("Positive doctor cases", t, func() {
		cases := []struct {
			name string
			args []string
		}{
			{"Simple cases", []string{"", "doctor"}},
			{"Enable collecting syslog", []string{"", "doctor", "--collect-log"}},
			{"Max 5 log entries", []string{"", "doctor", "--collect-log", "--limit", "5"}},
			{"Enable collecting pprof metric", []string{"", "doctor", "--collect-log", "--collect-pprof"}},
		}

		for _, c := range cases {
			Convey(c.name, func() {
				So(Main(c.args), ShouldBeNil)
			})

		}
	})

	Convey("Specify out dir", t, func() {
		Convey("Use default out dir", func() {
			So(Main([]string{"", "doctor"}), ShouldBeNil)
		})

		outDir := "./doctor/ok"
		Convey("Specify existing out dir", func() {
			if err := os.MkdirAll(outDir, 0755); err != nil {
				t.Fatalf("doctor error: %v", err)
			}
			So(Main([]string{"", "doctor", "--out-dir", outDir}), ShouldBeNil)
			if err := os.RemoveAll(outDir); err != nil {
				t.Fatalf("doctor error: %v", err)
			}
		})

		edgeCases := []struct {
			name   string
			outDir string
		}{
			{"Specify a non-existing out dir", "./doctor/out1"},
			{"Specify a file as out dir", "./doctor_test.go"},
		}
		for _, c := range edgeCases {
			Convey(c.name, func() {
				So(Main([]string{"", "doctor", "--out-dir", c.outDir}), ShouldNotBeNil)
			})
		}
	})
}
