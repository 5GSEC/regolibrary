package armo_builtins

import future.keywords.in

deny[msga] {
    workloads := [w | w = input[_]; w.kind == "WorkloadConfig"]
    work := workloads[_]

    pods := [p | p = input[_]; p.kind == "Deployment"]
    pod := pods[_]

    not labels_match(work, pod)

    msga := {
        "alertMessage": sprintf("Workload %v is not present", [pod.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [],
        "fixPaths": [],
        "alertObject": {
            "k8sApiObjects": [pod]
        }
    }
}

deny[msga] {
    workloads := [w | w = input[_]; w.kind == "WorkloadConfig"]
    work := workloads[i]

    pods := [p | p = input[_]; p.kind == "Deployment"]
    pod := pods[_]

    clusterpolicies := [policy | policy = input[_]; policy.kind == "ClusterPolicy"]
    labels_match(work, pod)
    cluster_policies_connected_to_pod := [policy | policy = clusterpolicies[_]; check_kyverno(work, policy)]
    count(cluster_policies_connected_to_pod) < 1
    
    missing_policies := [policy | policy = clusterpolicies[i]; not policy_in_workload_config(work, policy)]

    msga := {
        "alertMessage": sprintf("Workload %v does NOT have any Kyverno ClusterPolicy", [pod.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [],
        "fixPaths": [{"path": sprintf("Add ClusterPolicy %v to WorkloadConfig", [missing_policies[i].metadata.name]), "value":"false"}],
        "alertObject": {
            "k8sApiObjects": [pod]
        }
    }
}

deny[msga] {
    workloads := [w | w = input[_]; w.kind == "WorkloadConfig"]
    work := workloads[_]

    pods := [p | p = input[_]; p.kind == "Deployment"]
    pod := pods[_]

    clusterpolicies := [policy | policy = input[_]; policy.kind == "ClusterPolicy"]
    labels_match(work, pod)
    cluster_policies_connected_to_pod := [policy | policy = clusterpolicies[_]; check_kyverno(work, policy)]
    count(cluster_policies_connected_to_pod) > 0

    msga := {
        "alertMessage": sprintf("Workload %v does have Kyverno ClusterPolicy", [pod.metadata.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [],
        "fixPaths": [],
        "alertObject": {
            "k8sApiObjects": [pod]
        }
    }
}

policy_in_workload_config(work, policy) {
    some i
    some p
    wlpolicie := work.spec.workloads[i].policies[p]
    wlpolicie.name == policy.metadata.name
    wlpolicie.kind == policy.kind
}

check_kyverno(wlconfig, policy) {
    some i
    wlpolicie := wlconfig.spec.workloads[i].policies[_]
    policy.metadata.name == wlpolicie.name
}

# Function to check if labels match between work_list and pod
labels_match(work, pod) {
      some i
	  some key,value in work.spec.workloads[i].labels
      pod.metadata.labels[key] == value
}

wlConnectedToClusterPolicy(wl, policy) {
    count(policy.spec.match.resources.selector.matchLabels) == 0
}

wlConnectedToClusterPolicy(wl, policy) {
    count(policy.spec.match.resources.selector.matchLabels) > 0
    count({x | policy.spec.match.resources.selector.matchLabels[x] == wl.spec.template.metadata.labels[x]}) == count(policy.spec.match.resources.selector.matchLabels)
}
 
 