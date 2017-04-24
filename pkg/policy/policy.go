// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"crypto/sha512"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-policy")
)

// Privilege represents the privileges available to define for a policy node.
type Privilege byte

const (
	ALLOW Privilege = iota
	ALWAYS_ALLOW
	REQUIRES
	L4
)

var (
	privEnc = map[Privilege]string{
		ALLOW:        "allow",
		ALWAYS_ALLOW: "always-allow",
		REQUIRES:     "requires",
		L4:           "l4",
	}
	privDec = map[string]Privilege{
		"allow":        ALLOW,
		"always-allow": ALWAYS_ALLOW,
		"requires":     REQUIRES,
		"l4":           L4,
	}
)

func (p Privilege) String() string {
	if v, exists := privEnc[p]; exists {
		return v
	}
	return ""
}

func (p *Privilege) UnmarshalJSON(b []byte) error {
	if p == nil {
		p = new(Privilege)
	}
	if len(b) <= len(`""`) {
		return fmt.Errorf("invalid privilege '%s'", string(b))
	}
	if v, exists := privDec[string(b[1:len(b)-1])]; exists {
		*p = Privilege(v)
		return nil
	}

	return fmt.Errorf("unknown '%s' privilege", string(b))
}

func (p Privilege) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, p)), nil
}

type Tracing int

const (
	TRACE_DISABLED Tracing = iota
	TRACE_ENABLED
	TRACE_VERBOSE
)

func policyTrace(ctx *SearchContext, format string, a ...interface{}) {
	switch ctx.Trace {
	case TRACE_ENABLED, TRACE_VERBOSE:
		log.Debugf(format, a...)
		if ctx.Logging != nil {
			format = "%-" + ctx.CallDepth() + "s" + format
			a = append([]interface{}{""}, a...)
			ctx.Logging.Logger.Printf(format, a...)
		}
	}
}

func policyTraceVerbose(ctx *SearchContext, format string, a ...interface{}) {
	switch ctx.Trace {
	case TRACE_VERBOSE:
		log.Debugf(format, a...)
		if ctx.Logging != nil {
			ctx.Logging.Logger.Printf(format, a...)
		}
	}
}

type SearchContext struct {
	Trace       Tracing
	Depth       int
	Logging     *logging.LogBackend
	From        labels.LabelArray
	To          labels.LabelArray
	ToL4Ingress []*models.Port
	ToL4Egress  []*models.Port
}

type SearchContextReply struct {
	L3Decision api.ConsumableDecision
	L4Decision api.ConsumableDecision
}

// FinalDecision returns a decision for a L3 and L4 decision reply.
func (s *SearchContextReply) FinalDecision() api.ConsumableDecision {
	if s.L3Decision == api.ACCEPT || s.L4Decision == api.ALWAYS_ACCEPT {
		return s.L4Decision
	}
	return s.L3Decision
}

func (s *SearchContext) String() string {
	from := []string{}
	to := []string{}
	tol4ingress := []string{}
	tol4egress := []string{}
	for _, fromLabel := range s.From {
		from = append(from, fromLabel.String())
	}
	for _, toLabel := range s.To {
		to = append(to, toLabel.String())
	}
	for _, l4ingRule := range s.ToL4Ingress {
		tol4ingress = append(tol4ingress, fmt.Sprintf("%d/%s", l4ingRule.Port, l4ingRule.Protocol))
	}
	for _, l4egrRule := range s.ToL4Egress {
		tol4egress = append(tol4egress, fmt.Sprintf("%d/%s", l4egrRule.Port, l4egrRule.Protocol))
	}
	ret := fmt.Sprintf("From: [%s]", strings.Join(from, ", "))
	ret += fmt.Sprintf(" => To: [%s]", strings.Join(to, ", "))
	if len(tol4ingress) != 0 {
		ret += fmt.Sprintf(" AND to-L4-ingress: [%s]", strings.Join(tol4ingress, ", "))
	}
	if len(tol4egress) != 0 {
		ret += fmt.Sprintf(" AND to-L4-egress: [%s]", strings.Join(tol4egress, ", "))
	}
	return ret
}

func (s *SearchContext) CallDepth() string {
	return strconv.Itoa(s.Depth * 2)
}

// TargetCoveredBy checks if the SearchContext `To` is covered by the all
// `coverage` labels.
func (s *SearchContext) TargetCoveredBy(coverage []*labels.Label) bool {
	policyTrace(s, "Checking if %+v covers %+v", coverage, s.To)
	return s.To.Contains(coverage)
}

var (
	CoverageSHASize = len(fmt.Sprintf("%x", sha512.New512_256().Sum(nil)))
)
