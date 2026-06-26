// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: CC0-1.0

//go:build tools
// +build tools

// Tracks in a separate package to avoid kube conflicts

package tools

import _ "kubevirt.io/kubevirt/cmd/virtctl"
