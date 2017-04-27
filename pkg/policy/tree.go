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
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/policy/api"
)

// Tree overall policy tree.
type Tree struct {
	// Mutex protects the whole policy tree
	Mutex sync.RWMutex
	Root  *Node
}

// NewTree allocates and initializes a new policy tree
func NewTree() *Tree {
	tree := &Tree{}
	return tree
}

func canConsume(root *Node, ctx *SearchContext) api.ConsumableDecision {
	ctx.Depth++
	decision := api.UNDECIDED
	nmatch := 0
	defer func() {
		if nmatch != 0 {
			ctx.Depth--
		}
	}()

	for _, child := range root.Children {
		if child.Covers(ctx) {
			nmatch++
			policyTrace(ctx, "Coverage found in [%s], processing rules...\n", child.path)
			ctx.Depth++
			switch child.Allows(ctx) {
			case api.DENY:
				ctx.Depth--
				return api.DENY
			case api.ALWAYS_ACCEPT:
				ctx.Depth--
				return api.ALWAYS_ACCEPT
			case api.ACCEPT:
				decision = api.ACCEPT
			}
			ctx.Depth--
			policyTrace(ctx, "No conclusion in [%s] rules, current verdict: [%s]\n", child.path, decision)
		}
	}

	if nmatch == 0 {
		ctx.Depth--
		policyTrace(ctx, "No matching children in [%s]\n", root.path)
		return decision
	}

	for _, child := range root.Children {
		if child.Covers(ctx) {
			switch canConsume(child, ctx) {
			case api.DENY:
				return api.DENY
			case api.ALWAYS_ACCEPT:
				return api.ALWAYS_ACCEPT
			case api.ACCEPT:
				decision = api.ACCEPT
			}
		}
	}

	return decision
}

// AllowsRLocked checks the ConsumableDecision of the given `SearchContext`.
// Must be called with the Mutex's tree at least RLocked.
func (t *Tree) AllowsRLocked(ctx *SearchContext) SearchContextReply {
	policyTrace(ctx, "NEW TRACE >> %s\n", ctx.String())

	var l3Dec, l3SubDec, l4Dec api.ConsumableDecision
	// In absence of policy, deny
	if t.Root == nil {
		l3Dec = api.DENY
		policyTrace(ctx, "No policy loaded: [%s]\n", l3Dec.String())
		goto end
	}

	l3Dec = t.Root.Allows(ctx)
	policyTrace(ctx, "Root's [%s] rules verdict: [%s]\n", t.Root.path, l3Dec)
	switch l3Dec {
	case api.ALWAYS_ACCEPT:
		l3Dec = api.ACCEPT
		goto end
	case api.DENY:
		goto end
	}

	policyTrace(ctx, "Searching in [%s]'s children that have the coverage for: [%s]\n", t.Root.path, ctx.To)
	l3SubDec = canConsume(t.Root, ctx)
	policyTrace(ctx, "Root's [%s] children verdict: [%s]\n", t.Root.path, l3SubDec)
	switch l3SubDec {
	case api.ALWAYS_ACCEPT, api.ACCEPT:
		l3Dec = api.ACCEPT
	case api.DENY:
		l3Dec = api.DENY
	case api.UNDECIDED:
		if l3Dec == api.UNDECIDED {
			l3Dec = api.DENY
		}
	}

end:

	l4Policy := t.ResolveL4Policy(ctx)

	if l4Policy.CoversL4(ctx) {
		l4Dec = api.ACCEPT
	} else {
		l4Dec = api.DENY
	}
	decStr := strings.ToUpper(l3Dec.String())
	l4DecStr := strings.ToUpper(l4Dec.String())
	policyTrace(ctx, "END TRACE << l3 verdict: [%s], l4 verdict: [%s]\n", decStr, l4DecStr)

	return SearchContextReply{
		L3Decision: l3Dec,
		L4Decision: l4Dec,
	}
}

func (t *Tree) ResolveL4Policy(ctx *SearchContext) *L4Policy {
	result := NewL4Policy()

	policyTrace(ctx, "Resolving L4 policy for context %+v\n", ctx)

	if t.Root != nil {
		t.Root.ResolveL4Policy(ctx, result)
	}

	policyTrace(ctx, "Final tree L4 policy: %+v\n", result)
	return result
}

// LookupLocked returns a policy node and its parent for a given path.
// The `RootNodeName` is optional. If `path` is "", `node` will be the tree's
// root and `parent` will be `nil`.
//
// If `path` does not start with `RootNodeName`, it will be assumed `path` is a
// root's child. Thus, if `path` is a single node, the `parent` returned will be
// the tree's root.
func (t *Tree) LookupLocked(path string) (node, parent *Node) {
	// Empty tree
	if t.Root == nil {
		return nil, nil
	}

	path = removeRootPrefix(path)

	// "root." returns root node
	if path == "" {
		return t.Root, nil
	}

	node = t.Root
	parent = nil

	elements := strings.Split(path, NodePathDelimiter)
	for index, nodeName := range elements {
		if child, ok := node.Children[nodeName]; ok {
			parent = node
			node = child
		} else {
			// Return parent if we failed at last element
			if index == len(elements)-1 {
				return nil, node
			}
			return nil, nil
		}
	}

	return node, parent
}

// Add adds the provided policy node at the specified path.
func (t *Tree) Add(parentPath string, node *Node) (bool, error) {
	if node == nil {
		return false, nil
	}

	t.Mutex.Lock()
	defer t.Mutex.Unlock()

	return t.add(parentPath, node)
}

// AtomicReplace does an atomic operation for the provided subPath.subNode,
// addPath.addNode.
// The "path", "node" tuple will have the same behaviour use as other similar
// Tree functions.
//
// sub[Path|Node] represents the node that will be subtracted from the tree,
// this means the rules inside this node will be removed from rules of the node
// with the same path in the policy tree.
//
// add[Path|Node] represents the node that will be added/merged to the tree,
// this means the rules inside this node will be append to an existing node with
// the same path or, in case it doesn't exist in the tree, the node itself will
// be created.
// Examples:
// tree
// {
//   "root": [{coverage: world, accept: id.foo},{coverage: host, accept: id.foo}],
//   "children": ["id": [{coverage: foo, accept: root.bar}]
// }
//
// AtomicReplace("root", Node{coverage: world, accept: id.foo}, "", nil)
// // Expected result:
// tree
// {
//   "root": [{coverage: host, accept: id.foo}],
//   "children": ["id": [{coverage: foo, accept: root.bar}]
// }
//
// AtomicReplace("root", Node{coverage: host, accept: id.foo},
//               "root", Node{name: "id", coverage: foo, accept: id.foo})
// // Expected result:
// tree
// {
//   "root": [],
//   "children": ["id": [{coverage: foo, accept: root.bar},
//                       {coverage: foo, accept: id.foo}]
// }
func (t *Tree) AtomicReplace(subPath string, subNode *Node, addPath string, addNode *Node) (bool, error) {
	modified := false

	t.Mutex.Lock()
	defer t.Mutex.Unlock()

	if subPath != "" {
		if subNode == nil {
			rmNodeTree, rmNodeTreeParent := t.LookupLocked(subPath)
			if rmNodeTree != nil {
				t.deleteNode(rmNodeTree, rmNodeTreeParent)
				modified = true
			}
		} else {
			ln := JoinPath(subPath, subNode.Name)
			rmNodeTree, rmNodeTreeParent := t.LookupLocked(ln)
			if rmNodeTree != nil {
				for _, ruleToRm := range subNode.Rules {
					idx := rmNodeTree.PolicyRuleIdx(ruleToRm)
					if idx >= 0 {
						rmNodeTree.Rules = append(rmNodeTree.Rules[:idx], rmNodeTree.Rules[idx+1:]...)
						modified = true
					}
				}
				// If the rule was the last remaining, delete the node
				if !rmNodeTree.HasRules() {
					t.deleteNode(rmNodeTree, rmNodeTreeParent)
					modified = true
				}
			}
		}
	}

	if addPath == "" {
		return modified, nil
	}
	if addNode != nil {
		addNodeTree, _ := t.LookupLocked(JoinPath(addPath, addNode.Name))
		if addNodeTree == nil {
			return t.add(addPath, addNode)
		}
		addNode.Name = addNodeTree.Name
		modified, err := addNodeTree.Merge(addNode)
		if err != nil {
			return false, err
		}
		if modified {
			addNodeTree.ResolveTree()
		}
	}

	return modified, nil
}

// add adds the provided policy node at the specified path. Must be called with
// t.Mutex locked.
func (t *Tree) add(parentPath string, node *Node) (bool, error) {
	var err error

	if parentPath, err = node.NormalizeNames(parentPath); err != nil {
		return false, err
	}

	modified := false

	if parentPath == RootNodeName && node.Name == RootNodeName {
		node.Path()
		if t.Root == nil {
			t.Root = node
			modified = true
		} else {
			if modified, err = t.Root.Merge(node); err != nil {
				return false, err
			}
			// If modified we need to resolve the tree's root
			if modified {
				return true, t.Root.ResolveTree()
			}
		}
	} else {
		absPath := JoinPath(parentPath, node.Name)
		_, parent := t.LookupLocked(absPath)
		if parent == nil {
			grandParentPath, parentName := SplitNodePath(parentPath)
			parent = NewNode(parentName, nil)
			_, err := t.add(grandParentPath, parent)
			if err != nil {
				return false, fmt.Errorf("unable to add parent's node for path '%s': %s", parentPath, err)
			}
		}

		if modified, err = parent.AddChild(node.Name, node); err != nil {
			return false, err
		}
	}

	if modified {
		return true, node.ResolveTree()
	}

	return modified, nil
}

func (t *Tree) deleteNode(node, parent *Node) {
	if node == t.Root {
		t.Root = nil
	} else if parent != nil {
		delete(parent.Children, node.Name)
	}
}

func (t *Tree) Delete(path string, coverage string) bool {
	t.Mutex.Lock()
	defer t.Mutex.Unlock()

	node, parent := t.LookupLocked(path)
	if node == nil {
		return false
	}

	// Deletion request of a specific rule of a node
	if coverage != "" {
		for i, pr := range node.Rules {
			if prCover256Sum, err := pr.CoverageSHA256Sum(); err == nil &&
				prCover256Sum == coverage {
				node.Rules = append(node.Rules[:i], node.Rules[i+1:]...)

				// If the rule was the last remaining, delete the node
				if !node.HasRules() {
					t.deleteNode(node, parent)
				}

				return true
			}
		}

		return false
	}

	// Deletion request for entire node
	t.deleteNode(node, parent)

	return true
}
