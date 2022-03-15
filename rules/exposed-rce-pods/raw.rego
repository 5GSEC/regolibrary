package armo_builtins

deny[msga] {
  services := [ x | x = input[_]; x.kind == "Service" ]
  pods     := [ x | x = input[_]; x.kind == "Pod" ]
  vulns    := [ x | x = input[_]; x.kind == "ImageVulnerabilities"]

  pod     := pods[_]
  service := services[_]
  vuln    := vulns[_]

  # vuln data is relevant 
  count(vuln.data) > 0 

  # service is external-facing
  filter_external_access(service)

  # pod has the current service
  service_to_pod(service, pod) > 0

  # get container image name
  container := pod.spec.containers[i]

  # image has vulnerabilities
  container.image == vuln.metadata.name

  # At least one rce vulnerability
  filter_rce_vulnerabilities(vuln)

  relatedObjects := [pod, vuln]

  path := sprintf("status.containerStatuses[%v].imageID", [format_int(i, 10)])

  metadata = {
    "name": pod.metadata.name,
    "namespace": pod.metadata.namespace
  }

  external_objects = { 
    "apiVersion": "result.vulnscan.com/v1",
    "kind": pod.kind,
    "metadata": metadata,
    "relatedObjects": relatedObjects
  }

  msga := {
    "alertMessage": sprintf("pod '%v' exposed with rce vulnerability", [pod.metadata.name]),
    "packagename": "armo_builtins",
    "alertScore": 8,
    "failedPaths": [path],
    "fixPaths": [],
    "alertObject": {
      "externalObjects": external_objects
    }
  }
}

filter_rce_vulnerabilities(vuln) {
  data := vuln.data[_]
  data.categories.isRce == true
}

filter_external_access(service) {
  service.spec.type != "ClusterIP"
}

service_to_pod(service, pod) = res {
  service_selectors := [ x | x = service.spec.selector[_] ]

  res := count([ x | x = pod.metadata.labels[_]; x == service_selectors[_] ])
}