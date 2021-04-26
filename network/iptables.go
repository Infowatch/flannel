// Copyright 2015 flannel authors
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
// +build !windows

package network

import (
	"fmt"
	"strings"

	log "github.com/golang/glog"

	"time"

	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	"github.com/coreos/go-iptables/iptables"
)

const (
	FlannelFwdChain   = "FLANNEL-FORWARD"
	FlannelInputChain = "FLANNEL-INPUT"
)

type IPTables interface {
	NewChain(table, chain string) error
	AppendUnique(table string, chain string, rulespec ...string) error
	Delete(table string, chain string, rulespec ...string) error
	Exists(table string, chain string, rulespec ...string) (bool, error)
	Insert(table, chain string, pos int, rulespec ...string) error
}

type IPTablesRule struct {
	table    string
	chain    string
	pos      int
	rulespec []string
}

func MasqRules(ipn ip.IP4Net, lease *subnet.Lease) []IPTablesRule {
	n := ipn.String()
	sn := lease.Subnet.String()
	supports_random_fully := false
	ipt, err := iptables.New()
	if err == nil {
		supports_random_fully = ipt.HasRandomFully()
	}

	if supports_random_fully {
		return []IPTablesRule{
			// This rule makes sure we don't NAT traffic within overlay network (e.g. coming out of docker0)
			{table: "nat", chain: "POSTROUTING", rulespec: []string{"-s", n, "-d", n, "-j", "RETURN"}},
			// NAT if it's not multicast traffic
			{table: "nat", chain: "POSTROUTING", rulespec: []string{"-s", n, "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"}},
			// Prevent performing Masquerade on external traffic which arrives from a Node that owns the container/pod IP address
			{table: "nat", chain: "POSTROUTING", rulespec: []string{"!", "-s", n, "-d", sn, "-j", "RETURN"}},
			// Masquerade anything headed towards flannel from the host
			{table: "nat", chain: "POSTROUTING", rulespec: []string{"!", "-s", n, "-d", n, "-j", "MASQUERADE", "--random-fully"}},
		}
	} else {
		return []IPTablesRule{
			// This rule makes sure we don't NAT traffic within overlay network (e.g. coming out of docker0)
			{table: "nat", chain: "POSTROUTING", rulespec: []string{"-s", n, "-d", n, "-j", "RETURN"}},
			// NAT if it's not multicast traffic
			{table: "nat", chain: "POSTROUTING", rulespec: []string{"-s", n, "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE"}},
			// Prevent performing Masquerade on external traffic which arrives from a Node that owns the container/pod IP address
			{table: "nat", chain: "POSTROUTING", rulespec: []string{"!", "-s", n, "-d", sn, "-j", "RETURN"}},
			// Masquerade anything headed towards flannel from the host
			{table: "nat", chain: "POSTROUTING", rulespec: []string{"!", "-s", n, "-d", n, "-j", "MASQUERADE"}},
		}
	}
}

func ForwardRules(flannelNetwork string) []IPTablesRule {
	return []IPTablesRule{
		// These rules allow traffic to be forwarded if it is to or from the flannel network range.
		{table: "filter", chain: "FORWARD", pos: 1, rulespec: []string{"-m", "comment", "--comment", "flannel forwarding rules", "-j", FlannelFwdChain}},
		{table: "filter", chain: FlannelFwdChain, rulespec: []string{"-s", flannelNetwork, "-j", "ACCEPT"}},
		{table: "filter", chain: FlannelFwdChain, rulespec: []string{"-d", flannelNetwork, "-j", "ACCEPT"}},
	}
}

func InputRules(flannelNetwork string) []IPTablesRule {
	return []IPTablesRule{
		// These rules allow traffic to come to the flannel network range.
		{table: "filter", chain: "INPUT", pos: 1, rulespec: []string{"-m", "comment", "--comment", "flannel input rules", "-j", FlannelInputChain}},
		{table: "filter", chain: FlannelInputChain, rulespec: []string{"-s", flannelNetwork, "-j", "ACCEPT"}},
	}
}

func ipTablesRulesExist(ipt IPTables, rules []IPTablesRule) (bool, error) {
	for _, rule := range rules {
		exists, err := ipt.Exists(rule.table, rule.chain, rule.rulespec...)
		if err != nil {
			// this shouldn't ever happen
			return false, fmt.Errorf("failed to check rule existence: %v", err)
		}
		if !exists {
			return false, nil
		}
	}

	return true, nil
}

func SetupAndEnsureIPTables(rules []IPTablesRule, resyncPeriod int) {
	ipt, err := iptables.New()
	if err != nil {
		// if we can't find iptables, give up and return
		log.Errorf("Failed to setup IPTables. iptables binary was not found: %v", err)
		return
	}

	defer func() {
		teardownIPTables(ipt, rules)
	}()

	for {
		// Ensure that all the iptables rules exist every 5 seconds
		if err := ensureIPTables(ipt, rules); err != nil {
			log.Errorf("Failed to ensure iptables rules: %v", err)
		}

		time.Sleep(time.Duration(resyncPeriod) * time.Second)
	}
}

// DeleteIPTables delete specified iptables rules
func DeleteIPTables(rules []IPTablesRule) error {
	ipt, err := iptables.New()
	if err != nil {
		// if we can't find iptables, give up and return
		log.Errorf("Failed to setup IPTables. iptables binary was not found: %v", err)
		return err
	}
	teardownIPTables(ipt, rules)
	return nil
}

func ensureIPTables(ipt IPTables, rules []IPTablesRule) error {
	// Below we create uniq chains if they not exist yet
	tableChainUniqMap := make(map[string]struct{})
	for _, rule := range rules {
		tableChainKey := fmt.Sprintf("%s-%s", rule.table, rule.chain)
		if _, ok := tableChainUniqMap[tableChainKey]; !ok {
			if err := createChainIfNotExists(ipt, rule.table, rule.chain); err != nil {
				return err
			}
			tableChainUniqMap[tableChainKey] = struct{}{}
		}
	}

	exists, err := ipTablesRulesExist(ipt, rules)
	if err != nil {
		return fmt.Errorf("Error checking rule existence: %v", err)
	}
	if exists {
		// if all the rules already exist, no need to do anything
		return nil
	}

	// Otherwise, teardown all the rules and set them up again
	// We do this because the order of the rules is important
	log.Info("Some iptables rules are missing; deleting and recreating rules")

	teardownIPTables(ipt, rules)
	if err = setupIPTables(ipt, rules); err != nil {
		return fmt.Errorf("Error setting up rules: %v", err)
	}
	return nil
}

func createChainIfNotExists(ipt IPTables, table string, chain string) error {
	if err := ipt.NewChain(table, chain); err != nil {
		// Exit code 1 means the chain already exists
		if eerr, ok := err.(*iptables.Error); !ok || eerr.ExitCode() != 1 {
			return fmt.Errorf("failed to create chain: %v", err)
		}
	} else {
		log.Infof("New chain created: %s", chain)
	}

	return nil
}

func setupIPTables(ipt IPTables, rules []IPTablesRule) error {
	if err := appendRulesUniq(ipt, rules); err != nil {
		return err
	}

	return nil
}

func teardownIPTables(ipt IPTables, rules []IPTablesRule) {
	for _, rule := range rules {
		log.Info("Deleting iptables rule: ", strings.Join(rule.rulespec, " "))
		// We ignore errors here because if there's an error it's almost certainly because the rule
		// doesn't exist, which is fine (we don't need to delete rules that don't exist)
		ipt.Delete(rule.table, rule.chain, rule.rulespec...)
	}
}

func appendRulesUniq(ipt IPTables, rules []IPTablesRule) error {
	for _, rule := range rules {
		if rule.pos != 0 {
			log.Info("Inserting iptables rule: ", strings.Join(rule.rulespec, " "))
			exists, err := ipt.Exists(rule.table, rule.chain, rule.rulespec...)
			if err != nil {
				return fmt.Errorf("failed to insert IPTables rule: %v", err)
			}

			if exists {
				continue
			}

			if err := ipt.Insert(rule.table, rule.chain, rule.pos, rule.rulespec...); err != nil {
				return fmt.Errorf("failed to insert IPTables rule: %v", err)
			}
		} else {
			log.Info("Appending iptables rule: ", strings.Join(rule.rulespec, " "))
			err := ipt.AppendUnique(rule.table, rule.chain, rule.rulespec...)
			if err != nil {
				return fmt.Errorf("failed to insert IPTables rule: %v", err)
			}
		}
	}
	return nil
}
