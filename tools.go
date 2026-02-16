// SPDX-FileCopyrightText: Yalan Zhang <yalzhang@redhat.com>
//
// SPDX-License-Identifier: CC0-1.0

//go:build tools
// +build tools

// Package tools tracks build tool dependencies so they are included in go.mod.
// This enables hermetic builds by ensuring all tools are prefetched.
// See: https://github.com/go-modules-by-example/index/blob/master/010_tools/README.md
package tools

import (
	_ "github.com/mikefarah/yq/v4"
	_ "github.com/openshift/api/config/v1"
	_ "github.com/openshift/api/route/v1"
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen"
)
