package armo_builtins

deny[msga] {
    # workloads := input.spec.workloads
     		workloads := [w |  w= input[_]; w.kind == "WorkloadConfig"]
        work := workloads[_]
        work_list := work.spec.workloads[_]

        pods := [p | p = input[_]; p.kind == "ReplicaSet"]
        pod := pods[_]
      not all_labels_match(pod, work_list)

        msga := {
		"alertMessage": sprintf("Workload %v is not present", [work_list.workload_name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": []
		}
	}
}

deny[msga] {
    # workloads := input.spec.workloads
     		workloads := [w |  w= input[_]; w.kind == "WorkloadConfig"]
        work := workloads[_]
        work_list := work.spec.workloads[_]
        networkpolicies := [networkpolicie |  networkpolicie= input[_]; networkpolicie.kind == "NetworkPolicy"]
        pods := [p | p = input[_]; p.kind == "Pod"]
        pod := pods[_]
        all_labels_match(pod, work_list)


        msga := {
		"alertMessage": sprintf("Workload %v is not present", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [[pod]]
		}
	}
}

# Helper function to check if all required labels exist in pod labels
all_labels_match(pod, workload) {
    count(workload.labels) > 0
    count({x | workload.labels[x] == pod.metadata.labels[x]}) == count(workload.labels)
}

all_labels_match(pod, workload) {
    count(workload.labels) == 0
}

pod_connected_to_network_policy(pod, networkpolicie){
    count(networkpolicie.spec.podSelector) > 0
    count({x | networkpolicie.spec.podSelector.matchLabels[x] == pod.metadata.labels[x]}) == count(networkpolicie.spec.podSelector.matchLabels)
}

