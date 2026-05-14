// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import dpoption "github.com/cilium/cilium/pkg/datapath/option"

type Mode string

const (
	ModeUnspec     = Mode("")
	ModeAuto       = Mode(dpoption.DatapathModeAuto)
	ModeVeth       = Mode(dpoption.DatapathModeVeth)
	ModeLinuxRoute = Mode(dpoption.DatapathModeLinuxRoute)
	ModeNetkit     = Mode(dpoption.DatapathModeNetkit)
	ModeNetkitL2   = Mode(dpoption.DatapathModeNetkitL2)
)

func (mode Mode) IsLayer2() bool {
	switch mode {
	case ModeVeth, ModeLinuxRoute, ModeNetkitL2:
		return true
	default:
		return false
	}
}

func (mode Mode) IsNetkit() bool {
	switch mode {
	case ModeNetkit, ModeNetkitL2:
		return true
	default:
		return false
	}
}

func (mode Mode) IsVeth() bool {
	return mode == ModeVeth || mode == ModeLinuxRoute
}

func (mode Mode) String() string {
	switch mode {
	case ModeAuto:
		return dpoption.DatapathModeAuto
	case ModeVeth:
		return dpoption.DatapathModeVeth
	case ModeLinuxRoute:
		return dpoption.DatapathModeLinuxRoute
	case ModeNetkit:
		return dpoption.DatapathModeNetkit
	case ModeNetkitL2:
		return dpoption.DatapathModeNetkitL2
	default:
		return ""
	}
}

func ModeByName(mode string) Mode {
	switch mode {
	case dpoption.DatapathModeAuto:
		return ModeAuto
	case dpoption.DatapathModeVeth:
		return ModeVeth
	case dpoption.DatapathModeLinuxRoute:
		return ModeLinuxRoute
	case dpoption.DatapathModeNetkit:
		return ModeNetkit
	case dpoption.DatapathModeNetkitL2:
		return ModeNetkitL2
	default:
		return ModeUnspec
	}
}
