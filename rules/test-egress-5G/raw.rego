package armo_builtins

import future.keywords.in

# Define the input parameters
params := {
  "source_pod_labels": {"workload.nephio.org/oai": "smf"},
  "destination_pod_labels": {"workload.nephio.org/oai": "ausf"}
}

# Rule to check if a NetworkPolicy allows egress from source pod to destination pod
deny[msg] {
  input.kind == "NetworkPolicy"
  policy := input
  
  # Check if the policy applies to the source pod
  matches_source_pod(policy.spec.podSelector)
  
  # Check if the policy has egress rules
  "Egress" in policy.spec.policyTypes
  
  # Check if any egress rule allows connection to the destination pod
  not any_egress_rule_allows_destination(policy.spec.egress)
  
  msg := sprintf("NetworkPolicy %s does not allow egress from %v to %v", [policy.metadata.name, params.source_pod_labels, params.destination_pod_labels])
}

# Helper function to check if the policy applies to the source pod
matches_source_pod(podSelector) {
  all([params.source_pod_labels[k] == v | v = podSelector.matchLabels[k]])
}

# Helper function to check if any egress rule allows connection to the destination pod
any_egress_rule_allows_destination(egress_rules) {
  some rule in egress_rules
  some to in rule.to
  to.podSelector.matchLabels == params.destination_pod_labels
}
