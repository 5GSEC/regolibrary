package armo_builtins


oai_input := [
        {
            "workload_name": "CU-UP",
            "labels": [
                "app.kubernetes.io/name=oai-gnb-cu-up"
            ],
            "sensitive_asset_locations": [
                "/opt/oai-gnb/etc/gnb.conf",
                "/opt/oai-gnb/bin/nr-cuup",
                "/run/secrets/kubernetes.io/serviceaccount/"
            ],
            "egress": [
                "DU"
            ]
        },
        {
            "workload_name": "SMF",
            "labels": [
                "workload.nephio.org/oai=smf"
            ],
            "sensitive_asset_locations": [
                "/run/secrets/kubernetes.io/serviceaccount/",
                "/openair-smf/bin/oai_smf",
                "/openair-smf/etc/smf.yaml"
            ],
            "egress": [
                "UPF"
            ]
        },
        {
            "workload_name": "UPF",
            "labels": [
                "workload.nephio.org/oai=upf"
            ],
            "sensitive_asset_locations": [
                "/run/secrets/kubernetes.io/serviceaccount/",
                "/openair-upf/bin/oai_upf",
                "/openair-upf/etc/upf.yaml"
            ],
            "ingress": [
                "SMF"
            ]
        }
]

input_to_pods[oai, pod] := podnames {
	oai := oai_input[_]
	pod_name := oai_input.workload_name
	podnames := [podname | label := mock_pods.labels[_] 
									s := pod.metadata.labels[_]
									s  ]
}


# For pods
deny[msga] {
 		pods := [pod |  pod= input[_]; pod.kind == "Pod"]
		networkpolicies := [networkpolicie |  networkpolicie= input[_]; networkpolicie.kind == "NetworkPolicy"]
		pod := pods[_]
		network_policies_connected_to_pod := [networkpolicie |  networkpolicie= networkpolicies[_];  pod_connected_to_network_policy(pod, networkpolicie)]
		count(network_policies_connected_to_pod) > 0
        goodPolicies := [goodpolicie |  goodpolicie= network_policies_connected_to_pod[_];  is_ingerss_egress_policy(goodpolicie)]
		count(goodPolicies) < 1

    msga := {
		"alertMessage": sprintf("Pod: %v does not have ingress/egress defined", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}

}

# For pods
deny[msga] {
 		pods := [pod |  pod= input[_]; pod.kind == "Pod"]
		networkpolicies := [networkpolicie |  networkpolicie= input[_]; networkpolicie.kind == "NetworkPolicy"]
		pod := pods[_]
		network_policies_connected_to_pod := [networkpolicie |  networkpolicie= networkpolicies[_];  pod_connected_to_network_policy(pod, networkpolicie)]
		count(network_policies_connected_to_pod) < 1

    msga := {
		"alertMessage": sprintf("Pod: %v does not have ingress/egress defined", [pod.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {
			"k8sApiObjects": [pod]
		}
	}

}

pod_connected_to_network_policy(pod, networkpolicie){
	is_same_namespace(networkpolicie.metadata, pod.metadata)
    count(networkpolicie.spec.podSelector) > 0
    count({x | networkpolicie.spec.podSelector.matchLabels[x] == pod.metadata.labels[x]}) == count(networkpolicie.spec.podSelector.matchLabels)
}

pod_connected_to_network_policy(pod, networkpolicie){
	is_same_namespace(networkpolicie.metadata ,pod.metadata)
    count(networkpolicie.spec.podSelector) == 0
}
