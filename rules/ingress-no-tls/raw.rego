package armo_builtins

# Checks if Ingress is connected to a service and a workload to expose something
deny[msga] {
	ingress := input[_]
	ingress.kind == "Ingress"

	# Check if ingress has TLS enabled
	not ingress.spec.tls

	msga := {
		"alertMessage": sprintf("Ingress '%v' has not TLS definition", [ingress.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [{
        "path": "spec.tls",
        "value": "<your-tls-definition>"
        }],
		"alertScore": 7,
		"alertObject": {"k8sApiObjects": [ingress]}
	}
}
