package armo_builtins

import future.keywords.in

deny[msga] {
    # workloads := input.spec.workloads
     	workloads := [w |  w= input[_]; w.kind == "WorkloadConfig"]
        work := workloads[_]
        # work_list := work.spec.workloads[_]

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

     	workloads := [w |  w= input[_]; w.kind == "WorkloadConfig"]
        work := workloads[_]

        pods := [p | p = input[_]; p.kind == "Deployment"]
        pod := pods[_]

		networkpolicies := [networkpolicie |  networkpolicie= input[_]; networkpolicie.kind == "NetworkPolicy"]
        labels_match(work, pod)
		network_policies_connected_to_pod := [networkpolicie |  networkpolicie= networkpolicies[_];  wlConnectedToNetworkPolicy(pod, networkpolicie)]
		count(network_policies_connected_to_pod) < 1


        msga := {
		"alertMessage": sprintf("Workload %v does NOT have a network policy", [pod.metadata.name]),
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

     	workloads := [w |  w= input[_]; w.kind == "WorkloadConfig"]
        work := workloads[_]

        pods := [p | p = input[_]; p.kind == "Deployment"]
        pod := pods[_]

		networkpolicies := [networkpolicie |  networkpolicie= input[_]; networkpolicie.kind == "NetworkPolicy"]
        labels_match(work, pod)
		network_policies_connected_to_pod := [networkpolicie |  networkpolicie= networkpolicies[_];  wlConnectedToNetworkPolicy(pod, networkpolicie)]
		count(network_policies_connected_to_pod) > 0
	    goodPolicies := [goodpolicie |  goodpolicie= network_policies_connected_to_pod[_];  is_ingerss_egress_policy(goodpolicie)]
	    count(goodPolicies) < 1


        msga := {
		"alertMessage": sprintf("Workload %v does NOT have an Ingress/Egress Policy", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}
}
# Function to check if labels match between work_list and pod
labels_match(work, pod) {
      some i
	  some key,value in work.spec.workloads[i].labels
      pod.metadata.labels[key] == value
}

wlConnectedToNetworkPolicy(wl, networkpolicie){
    count(networkpolicie.spec.podSelector) == 0
}


wlConnectedToNetworkPolicy(wl, networkpolicie){
	count(networkpolicie.spec.podSelector) > 0
    count({x | networkpolicie.spec.podSelector.matchLabels[x] == wl.spec.template.metadata.labels[x]}) == count(networkpolicie.spec.podSelector.matchLabels)
}

is_ingerss_egress_policy(networkpolicie) {
    list_contains(networkpolicie.spec.policyTypes, "Ingress")
    list_contains(networkpolicie.spec.policyTypes, "Egress")
 }

list_contains(list, element) {
  some i
  list[i] == element
}
