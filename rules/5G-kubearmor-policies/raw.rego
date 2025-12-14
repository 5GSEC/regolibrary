package armo_builtins

import future.keywords.in

deny[msga] {
    # Rule 1: Deployment must belong to some WorkloadConfig
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
    # Rule 2: Deployment references KubeArmorPolicy that is missing
    workloads := [w | w = input[_]; w.kind == "WorkloadConfig"]
    work := workloads[_]

    pods := [p | p = input[_]; p.kind == "Deployment"]
    pod := pods[_]

    labels_match(work, pod)

    # Check all policies referenced in WorkloadConfig
    pr := work.spec.workloads[_].policies[_]
    pr.kind == "KubeArmorPolicy"

    not policy_ref_exists(pr)

    msga := {
        "alertMessage": sprintf("Deployment %v requires KubeArmorPolicy %v which is missing", [pod.metadata.name, pr.name]),
        "packagename": "armo_builtins",
        "alertScore": 7,
        "failedPaths": [],
        "fixPaths": [{"path": sprintf("Add KubeArmorPolicy %v to the cluster", [pr.name]), "value": ""}],
        "alertObject": {
            "k8sApiObjects": [pod]
        }
    }
}

policy_ref_exists(pr) {
    some i
    input[i].kind == "KubeArmorPolicy"
    input[i].metadata.name == pr.name
}

# Function to check if labels match between WorkloadConfig and Deployment
labels_match(work, pod) {
    some i
    some key, value in work.spec.workloads[i].labels
    pod.metadata.labels[key] == value
}
