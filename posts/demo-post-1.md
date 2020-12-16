---
title: 'The city of hipsters'
author: 'Netlifriends'
date: '2020-04-27'
hero_image: ../static/milkovi-seattle-unsplash.jpg
---

# {KUBERNETES} Table of Content
[[TOC]]


# General
* backed by google and has a long history (in container's term)
* currently managed by Linux foundation
* google also provide GKE (Google Container Engine) built on top of it
* supports both docker and rtk
* bad UI
* container-agnostic orchestration system
    * docker is one of the supported run-time
    * and currently the only one officially
* documentation is sub par but Slack and Stackoverflow community is very active
* [apache license](https://github.com/kubernetes/kubernetes/blob/master/LICENSE)
    * kubernetes/LICENSE at master · kubernetes/kubernetes · GitHub
* GFW, Aliyun repo: `registry.cn-hangzhou.aliyuncs.com/google_containers`
* quarterly release cycle

## Ideology
* k8s has gone backwards in burning developer with details of the infrastructure


## History
* originated from Google internal project Borg (now called Omega)
* open sourced in 2014
* 1.0: July 2015
* graduated from CNCF (first project to do so) in March 2018


# Terminologies
* node
    * a worker machine in k8s
    * also called minion
* pod
    * a smallest deployable unit
    * logical collection of containers that belong to an application
    * containers that **should** go hand in hand together as if they were in
      a single physical host
    * has single shared unique **dynamic** virtual IP
    * shared volume
    * most of the time it has a single container
    * think of it as a way of running multiple processes with container
    * share
        * `-net=container:bla`
        * `-ipc=container:bla`
        * volume
        * PID name space
        * time namespace
    * there is a `pause` container that holds the network namespace for all other
      containers that has separate life cycle
        * [so](http://stackoverflow.com/questions/33472741/what-work-does-the-process-in-container-gcr-io-google-containers-pause0-8-0-d)
            * docker - What work does the process in container &quot;gcr.io/google_containers/pause:0.8.0&quot; do? - Stack Overflow
* replica set
    * in terms of pods
    * k8s maintain user specified number of pods in a set
    * kill or add pod when necessary
    * replaces replication controller
* replication controller
    * takes care of one or more pods
    * make sure of the correct number of pods are running
    * this is an k8s object that's injected into the cluster, not a daemon like
      kubelet
* deployments
    * declarative update for pods/replica set
    * describe only desired state
    * image, cpu, mem, envar
    * it's like app configuration
    * uses replication set
    * deployment file are pretty much like docker compose file
    * `Deployment -> Replica Set -> Pod(s)`
        * RS gets automatically created
    * `apiVersion: extensions/v1beta1`
    * `kind: Deployment`
    * higher level concepts than replication set
    * `Deployment.spec.revisionHistoryLimit: 100` asks to store 100 history
        * default is 10
    * rolling update
        * pods are updated one by one, k8s service ensures that only the healthy pod gets traffic
* service
    * abstraction on top of pod
    * provides single static virtual IP and DNS name
    * provides load balancing
    * a named load balancer
    * can be exposed both externally and internally to the cluster
    * can also expose non-k8s endpoints
* label
    * key/value pair attached to an object, such as pod
    * used to group pods, etc
    * values are restricted to `[a-zA-Z0-9]-_`
        * annotation doesn't have such restriction
* selector
    * the other side of label
    * can be used to search for pod, etc
* namespace
    * total separation of environments
    * e.g `staging`, `production`
* kubernetes has an implicit assumption that all the state that is shared
  between service instances (e.g. a Mongo cluster that stores user profiles) is
  managed outside of Kubernetes.
    * [from here](https://opensource.com/business/14/12/containers-microservices-and-orchestrating-whole-symphony)


# Components
## Cluster Components
* master
    * manages a number of nodes
    * HA is available
    * runs API server, scheduler, and controllers
    * scheduler decides where a pod goes into the cluster
    * essentially it's just a node running master processes
    * typically doesn't run pods
* node
    * also called minion
    * manages pods, volume, secretes, etc
    * health check
    * proxy for port forwarding, etc
    * runs kubelet, kube-proxy and things like fluentd
    * also runs optional addons like dns, dashboard UI

## Software Components
* etcd
    * lightweight key-value data store
    * distributed database
    * can be configured to form a cluster automatically
* API Server
    * serves kubernets API over HTTP+JSON
    * kubernetes API
    * extension API
    * autoscaling API
    * batch API
* scheduler
    * monitors resource and decide which pod runs on which node
* controller manager
    * makes sure the current status matches user's desire
* kubelet
    * runs on nodes, drives pod stat towards desired one
* kube-proxy
    * _Communication between pods in Kubernetes is managed by the Service resource. By default, this resource creates a virtual IP address: the ClusterIP. When a pod decides it wants to talk to another service, DNS returns the cluster IP of this service. As the pod tries to connect to the cluster IP, iptables on the local node has been configured to pick a destination pod IP address randomly. kube-proxy is in charge of configuring iptables on each node in the cluster and does this whenever a service is changed, a pod starts or stops. These changes happen on every node and because of iptables implementation details are extremely expensive._
        * [here](https://linkerd.io/2020/02/17/architecting-for-multicluster-kubernetes/)
    * forward network traffic looking for cluster IP service to their endpoint
    * runs on every node
    * network proxy and load-balancer
    * monitors API from master
    * uses virtual IP and `iptables`
    * at one stage it was a real proxy that packets pass through
    * userspace mode -> iptable -> moved on to use ipvs
    * [debug kube proxy](https://kubernetes.io/docs/tasks/debug-application-cluster/debug-service/#is-the-kube-proxy-working)
        * with iptable rule examples
        * `KUBE-SVC-*` rule and `KUBE-SEP-*` rule
    * [k8s blog, 2019, bug](https://kubernetes.io/blog/2019/03/29/kube-proxy-subtleties-debugging-an-intermittent-connection-reset/)
        * a war story about a bug, with clear explanation of iptables programmed by kube-proxy
        * `KUBE-SERVICES` - entrypoin, points to `KUBE-SVC` chain
        * `KUBE-SVC-*` chain - one per clusterIP service, load balanced to `KUBE-SEP-*` chain
        * `KUBE-SEP-*` chain - one per service endpoint, simple DNAT
    * [prefetch](https://prefetch.net/blog/2018/02/09/understanding-the-network-plumbing-that-makes-kubernetes-pods-and-services-work/)
        * with actual iptable chain examples
    * [ipvs, k8s.io, 2018](https://kubernetes.io/blog/2018/07/09/ipvs-based-in-cluster-load-balancing-deep-dive/)
        * iptable is a bottle neck for scaling
        * ipvs uses hash table that scales much better
        * scheduler can be configured: round robin, destination hashing, etc
        * there is actually a `kube-ipvs0` dummy device that has the cluster IP
        * one IPVS virtual server per service IP
        * `ipvsadm -ln` [gist](https://gist.github.com/674e275a47d4328befe24a666edd045c)
    * [cli, reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-proxy/)
        * kube-proxy command line reference
    * [chiao, detail](https://arthurchiao.github.io/blog/cracking-k8s-node-proxy/)
        * **Cracking kubernetes node proxy (aka kube-proxy)**
* cAdvisor
    * monitoring agent
    * `kubectl proxy` && GET `/api/v1/nodes/${1}/proxy/metrics/cadvisor`

## Arch
### High Level Architecture
<img alt="arch" src="http://k8s.info/resources/cheatsheet/k8s-cheatsheet-physical-layout.png" width=75%>

### 2
<img alt="another arch" src="http://cythumb.cyworld.com/810x0/c2down.cyworld.co.kr/download?fid=64224fe7c9ab420678b250019c2ac900&name=2015_09_25_kubernetes_architecture_with_flannel.png" width=75%>

### 3
<img alt="black and white" src="http://blog.octo.com/wp-content/uploads/2017/01/architecturenormal-1024x843.png" width=75%>

### with edge router
<img src="https://cdn-images-1.medium.com/max/1600/1*_ArjfIk34Op6qQWoYCPhOA.png" width=75%>


# Functionality

## Resource Map @@
<img src="http://borlandc.pek3b.qingstor.com/k8s/k8s-resource-map.jpeg" width="75%">

## Ring Graph @@
<img src="http://borlandc.pek3b.qingstor.com/k8s/k8s-rings.png" width=65%>

## Top 10 Patterns @@
<img src="http://borlandc.pek3b.qingstor.com/k8s/top_10_kubernetes_patterns.png"> 

from _Kubernetes Patterns_

## Health check
* liveness probe checks if the container is broken and should be restarted
    * this is only necessary if the application is **not** able to crash itself.
* readiness probe
    * check if the service is ready, e.g. depending service like mysql, redis, are ready
    * k8s will only send traffic to the pod if it's ready
* both probes are periodical
* both support three types of diagnose: http, tcp and command line
* `deploymentspec.restartPolicy`
    * values can be `Always` (default), `OnFailure`, and `Never`
    * applies to all containers
* [article by ianlewis](https://www.ianlewis.org/en/using-kubernetes-health-checks)
* [think twice before using helm](https://medium.com/virtuslab/think-twice-before-using-helm-25fbb18bc822)
* [dangerous](https://srcco.de/posts/kubernetes-liveness-probes-are-dangerous.html)
    * **LIVENESS PROBES ARE DANGEROUS**

## Composing
* pod definition in YAML
* also possible to use JSON

## Configuration Management
* config map and secretes
* secretes can be accessed from volume files or environment variable
* updated secretes are NOT handled automatically
* ConfigMaps are meant for non-secure informations
    * can support JSON blobs and entire files
* ConfigMaps can be used as
    * envvar
    * file in volume
        * automatically updated but it takes a while
    * docker run command line
* [giantswarm](https://blog.giantswarm.io/understanding-basic-kubernetes-concepts-iv-secrets-and-configmaps/)
* [k8s技术社区](https://mp.weixin.qq.com/s?__biz=MzI4NDYxOTgwMw==&mid=2247483735&idx=1&sn=5b7479abd4d0f087bf8f5459d4a6333a&chksm=ebf9e423dc8e6d35a57fb36df2e4499c5d28f90ba76625ca338e8775a5246e6ee9eb3bb4adf0&mpshare=1&scene=1&srcid=0413rcM3LonF0Za813KVw1Yw&key=c006b033843dca2ee6bc8cc04ddeb9e55487b95915484e764697c4c94ce622bd9f6ca3888575d511b9e1b85ecdaa1debef744509477167c6b052de4105b0754bac7776773f686e99e9d97386ca684c8d&ascene=0&uin=MjIxNDYyOTkwMg%3D%3D&)

## Scheduling
## PDB
* `poddisruptionbudget`
* specifies tolerated number of pods to keep alive, making sure that there are
  some left
    * `kubectl create pdb my-pdb --selector=app=nginx --min-available=70%`
* this will be observed by pod **eviction**
    * which is the difference between `delete` and `evict`


## Resource
* `v1/ResourceQuota` object
    * one or more per namespace
* once quota is enabled, user must specify request or limits for those values
* `--admission-control=`
* quota can be set for computatation resources as well as kubernetes objects
  like service, etc
* `requests.foo` makes explict request for resources
* `limits.foo` specifies explict limits for resources
* `foo` can be `cpu`, and `memory`, etc
* memory is total resident set size (RSS) and page cache, swap is disabled so not included
    * [here](https://medium.com/expedia-group-tech/kubernetes-container-resource-requirements-part-1-memory-a9fbe02c8a5f)
        * pretty nice article, explaining memory limit
    * [so, RSS](https://stackoverflow.com/questions/7880784/what-is-rss-and-vsz-in-linux-memory-management)
* 1 CPU == 1 hyperthread in a Intel processor
* `LimitRange` sets resource usage limits for each kind of resource in a Namespace.
    * [demo](https://github.com/thockin/micro-demos/blob/master/quota/limits.yaml)
* [sysdig, oom, trouble](https://sysdig.com/blog/troubleshoot-kubernetes-oom/)
    * **How to troubleshoot Kubernetes OOM and CPU Throttle**
    * _Despite this mechanism, we can still finish up with system OOM kills as Kubernetes memory management runs only every several seconds. If the system memory fills too quickly, the system can kill Kubernetes control processes, making the node unstable._
    * _using CPU can never be the reason of Kubernetes killing a container._
    * ❓ not sure I fully understand the CPU throttling part


## Security Context
* defines privilege for a Pod as part of a pod spec
* `runAsUser: 1000`
    * ‼️  has **both** Pod level and container level definitions
* `runAsGroup: 555`
* `capabilities`

## Pod Security Policy

## Secrets
* `v1/Secret`
* defined as k/v pairs
* `kubectl create secret <docker-registry, generic, tls>`

### Access
* volume: `volumes.secret`
    * mounted as directory matching secrete name, under which
    * file name matches key
    * file content matches value
* envar: `env.valueFrom.valueFrom`
    * with `name` and `key` to access the value

## CLI
* `kubectl get quota --namespace=myspace`
* `kubectl describe quota compute-resources --namespace=myspace`
* `kubectl describe quota object-counts --namespace=myspace`

## Links
* [official](https://kubernetes.io/docs/concepts/policy/resource-quotas/)
* [official practical](https://kubernetes.io/docs/tasks/administer-cluster/quota-api-object/)


## Service
* session affinity can be specified in service `spec`
    * `spec.sessionAffinity`, value can be `ClientIP` or `None`
    * generates separate iptable run from kube-proxy
* when a service is created without selectors, the `Endpoints` object is not
  going to be created and has to be defined by the user
    * suitable for defining external services
* service handles layer 4 routing, while ingress handles layer 7
* service can expose more than one port
    * each port shoud be named in this case
* service can be discovered by environment variable
    * when a new pod is created, existing service will be available in the pod
      via envar
    * `XXX_SERVICE_HOST`, `XXX_SERVICE_PORT`
* service can also be discovered by DNS
* `externalTrafficPolicy=local` is an annotation on the Kubernetes service resource that can be set to preserve the client source IP.
    * By setting ExternalTrafficPolicy=local, nodes only route traffic to pods that are on the same node, which then preserves client IP

### Service types
* `ClusterIP`
    * this is the default type
    * enable pod to pod communication
    * provides service discovery
    * provides DNS
    * only accessible from inside the cluster
    * `None`: for **headless** service
    * `""`: automatic assigned from a special IP segment
    * `x.x.x.x`: pre-allocated IP
* `NodePort`
    * a port on a node
    * externally exposed service
    * once exposed, the port is available on all nodes
    * builds on top of cluster ip and route request from all nodes on that port
    * can be specified by user, default is automatic
        * default automatic range is 30000-32767, user configurable
* `LoadBalancer`
    * external IP acting as a load balancer
    * actual load balancer provided by the **cloud provider**
    * builds on top of `NodePort` and creates an load balancer
    * `type: LoadBalancer`
    * `kubectl expose --type=LoadBalancer`
* `ExternalName`
    * DNS alias for external services
    * this doesn't involve `kube-proxy`
    * no port or endpoint is defined
    * `my-service.prod.svc.CLUSTER` points to name in `spec.my.database.example.com`
    * add an CNAME record into kube-dns
* `externalIPs`
    * not sure when it was added
    * expose through node external IP
    * can work with any service type
    * external IP themself is not managed by kubernetes
    * e.g. `externalIPs: [80.11.12.10,]`

### Headless service
* service with `ClusterIP` set to `None`
* no IP will be configured and thus no iptable rules will be created
* DNS entries are added depending on whether there is selector or not

### EndPointSlices
* eps tries the scaling problem with ep.
* before introduciton of eps, 1 svc has 1 ep. now 1 svc has N eps, each of which can be individually udpated
    * when a pod is added or removed
* GA in 1.19, EndPoints is still GA
* [kubernetes blog](https://kubernetes.io/blog/2020/09/02/scaling-kubernetes-networking-with-endpointslices/)
    * with picture

## Deployment
* `spec.strategy`
    * controls upgrade strategy
    * `.type`: `Recreate`  or `RollingUpdate` (default)
* `kubectl rollout status deploy/foo`
    * check rollout status
* `kubectl rollout history deploy/foo`
    * check rollout history
* `kubectl rollout undo deploy/foo`
    * rollback to previous version
    * can also rollback to a specific version with e.g. `--to-version=2`
* a rollout is triggered when part of `.spec.template` is modified

## DaemonSet
* ensure that a pod is available on selected nodes
* `RestartPolicy` has to be `Always`
* `spec.nodeSelector` can be used to select node

## Jobs
* `kind: Job`
* pods that run for a while and stop and not to be restarted
* 3 kinds
    * non-parallel jobs
    * parallel jobs with a fixed completion count `spec.completions`
        * controls how many completions is desired
    * parallel jobs with a work queue: `spec.parallelism`
        * controls number of pod running at the same time

## CronJob
* `kind: CronJob`
* `spec.schedule: "*/1 * * * *"`
* available from 1.5+
* API server has to be started with `--runtime-config=batch/v2alpha1=true`

## Init Containers
* a feature added in 1.5
* within a pod, a set of containers can be specified to run before the app containers.
* different to regular containers
    * run to completion
    * runs one after another
* `metadata.annotation.pod.beta.kubernetes.io/init-containers`
    * 1.5 +
* `spec.initContainers`
    * 1.6 +

## Lifecycle Hooks
* `postStart` in container spec
    * called right after container creation
    * blocking all following operations
    * no gurantee that it'll be triggered before `ENTRYPOINT`
    * no parameter
* `preStop` in container spec
    * blocking, stop only happens when hook handler returns
* hook handler can be
    * shell script: `exec`
    * HTTP: `httpGet`
* hooks are delivered at least once
* [openshift](https://blog.openshift.com/kubernetes-pods-life/)
    * blog about pod lifecycle

## Affinity
* `spec.nodeSelector` provides simple way of scheduling pods on host
* node affinity introduced in 1.2, rather flexible syntax allowed
* inter-pod affinity introduced in 1.4
* can be
    * `nodeAffinity`
    * `podAffinity`
    * `podAntiAffinity`
    * there is no `nodeAntiAffinity`
* `spec.affinity.nodeAffinity`
    * `requiredDuringSchedulingIgnoredDuringExecution`
    * `preferredDuringSchedulingIgnoredDuringExecution`
        * for preferred, `weight` is required
* operator supported
    * `In`
    * `NotIn`
    * `Exists`
    * `DoesNotExists`
    * `Gt`
    * `Lt`

## Taint and toleration
* related to node/pod affinity
* taint roughly means _mark_
* `kubectl taint nodes node1 key=value:NoSchedule`
    * pod cannot be scheduled on this node `node1`
    * unless there is a toleration that matches the KV pair and effect
      `NoSchedule`
* effect
    * `NoSchedule` no pod will be scheduled
    * `PreferNoSchedule` same as above but soft
    * `NoExecute` evict pod from node
* toleration is declared inside a **pod spec** to make exception to the above rule
    * key
    * value
    * operation: `Exists, Equal`
    * effect

## StatefulSet
* mimics virtual machine
    * stable, unique network ID:
        - `{statefulset-name}-{ordinal}`
        - each pod gets: `podname.headless_service_name` as DNS
    * stable, persistent storage
    * **stable** means persistence across pod reschedule
* used to be called **PetSets**
* beta from 1.5
* includes
    * a headless service that controls the domain `$svc.$ns.svc.cluster.local`
    * stateful set, the application itself, e.g. nginx
    * volume claim templates, each replicate will have its own PVC
* meant for service with
    * a pre-defined cluster size
    * network attached shared storage
* replicas will be brought up one after another: `{0 ... N-1}`
    * deletion reverses the order
* nodes can communicate with one another through stable network names
    * point of the headless service
* can be scaled through hpa
    * [here](https://raw.githubusercontent.com/janakiramm/wp-statefulset/master/wordpress.yml)
    * how successful this operation is depends on the actual application that's 
      being scaled
    * when scaling down, the pvc and pv won't be removed, so that when it's
      scaled up again, they'll be reused, retaining the data
* each pod
    * has stable hostname `statefullsetname-ordinal`
    * has `$podname.$service-name`
* leadership select can thus be performed
* data on pvc will be retained even if the set is scaled down or deleted
* `spec.serviceName` must point to the headless that pre-exists
    * pod get DNS entry like `pod-specific-string.serviceName.default.svc.cluster.local`
* `terminationGracePeriodSeconds` cannot be 0
* Pod Management Policies
    * `Parallel` states that pod will not be updated in a rolling manner
* [blog](http://blog.kubernetes.io/2016/12/statefulset-run-scale-stateful-applications-in-kubernetes.html)
* [mysql](https://github.com/Yolean/kubernetes-mysql-cluster)
    * github repo for running mysql cluster
* [newstack](https://thenewstack.io/deploy-highly-available-wordpress-instance-statefulset-kubernetes-1-5/)
    * deploying wordpress with statefulset and pv
* [cockroach](https://raw.githubusercontent.com/cockroachdb/cockroach/master/cloud/kubernetes/cockroachdb-statefulset.yaml)
    * example deploy

## ConfigMap
* config can be exported to
    * envar
    * command line argument
    * config file in volume
* creation
    * `kubectl create configmap my-config`
    * `--from-literal=literal-key=literal-value`
    * `--from-file=ui.properties`
    * `--from-file=path/to/config/dir`
* consumption
    * `valueFrom: {configMapKeyRef: bla}`
    * `volumes[].configMap`

## Namespace
* by default, there are 2: `default` and `kube-system`
* one can create new namespaces with YAML file (`kind: Namespace`)
    * or directly with `kubectl create ns`
* `kubectl config set-context <context> --namespace=test`
    * sets the current namespace
* `kubectl create -f foo.yaml --namespace wisebuild`
    * create objetcs inside a namespace
* namespace can also be specified in YAML files
* namespace cannot be nested
* network is not firewalled between namespaces

### DNS
* `<service-name>.<namespace-name>.svc.cluster.local`
* name must be DNS-1035 valid: `'[a-z]([-a-z0-9]*[a-z0-9])?`
    * this applies only to service and not pod or deployment
* `hostname.subdomain.namespace.svc.....`
    * `pod.spec.hostname` over `pod.metadata.name`
* `kubectl run --generator=run-pod/v1 tmp-shell --rm -i --tty --image nicolaka/netshoot -- /bin/bash`
    * handy command to run netshoot


## Ingress
* an Ingress is a collection of rules that allow inbound connections to reach the cluster **services**.
* `internet ==> Ingress ==> Services`
* benefits:
    * virtual domain
    * TLS termination
* requires a ingress controller to be deployed on the master node
* a ingress controller:
    * is a reverse proxy that's kubernetes aware
    * watches creation/update/deletion of rules
    * configure itself accordingly
    * not part of `kube-controller-manager`
    * officially nginx controller is supported as well as GCE
    * requires default backend for ingress
* ingress resource
    * `kind: Ingress`
    * `spec.rules`
* multple ingress controller can run in parallel
    * `annotations:`
        * `kubernetes.io/ingress.class: "gce"`
* [nginx ingress controller](https://github.com/kubernetes/ingress/blob/master/controllers/nginx/README.md)
    * receive events from k8s and update config file 
    * reload configuration when needed
    * borrows stuff from openresty
    * customizable from annotation
    * [customize annotation](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/)
        * with loads of canary related settings
* [ga, 1.19, 2020](https://opensource.googleblog.com/2020/09/kubernetes-ingress-goes-ga.html)
    * **Kubernetes Ingress Goes GA**

### Philosophy
<img src="https://pbs.twimg.com/media/DZVaE83U8AAMyqh.jpg" width=75%>

### Links
* [traffik](https://docs.traefik.io/user-guide/kubernetes/)
    * official user guide for traffik
* [hackernoon](https://hackernoon.com/kubernetes-ingress-controllers-and-traefik-a32648a4ae95)
    * pratical article of using trafik as a ingress controller
    * deploying trafik only on **edge router** nodes is a nice idea
* [crondev](https://crondev.com/kubernetes-nginx-ingress-controller/)
    * nginx controller
* [deploy](https://github.com/kubernetes/ingress-nginx/blob/master/deploy/README.md)
    * official deploy document
    * on baremetal, it's a deployment with nodeport
* [speakerdeck, ingress, dns, ipv6, thockin](https://speakerdeck.com/thockin/sig-network-deep-dive-kubecon-eu-2019?slide=33)
    * SIG-Network Deep-Dive, KubeCon EU 2019
    * a large part of it is what's wrong with current ingress and how to fix them.

## Downward API
* mechanism to expose pod level information to container
* info can be exposed to
    * envar
    * volume file
* envar
    * `env.valueFrom.fieldRef`
    * `fieldPath: spec.nodeName`
    * `fieldPath: metadata.namespace`

## Autoscaling
* HPA
* `kind: HorizontalPodAutoscaler`
* `kubectl` can specify policies directly 
* `kubectl get hpa`
* seems to only support CPU at the moment
* require **heapster** for collecting metrics
    * in turn requires storage solution like influxdb

## Admission Webhook
* hook for customized logic on job admission
    * job filtering (reject/allow)
    * object injection
    * mutation - modify object
* two types: `MutatingAdmissionWebhook`, `ValidatingAdmissionWebhook`
* just a basic HTTP server that works with a particular API
    * has to be TLS enabled so preparing certs is a pain
    * k8s API server uses CA bundle to access secure webhooks server
* configured through:
    * `ValidatingWebhookConfiguration`
    * `MutatingWebhookConfiguration`
* different from initializer
* usage:
    * mutate resource before creating them
    * automatic provisioning of storage class
    * validation
    * namespace restriction
* debug
    * `kc describe rs ....` can see something
* [ibm](https://medium.com/ibm-cloud/diving-into-kubernetes-mutatingadmissionwebhook-6ef3c5695f74)
    * Diving into Kubernetes MutatingAdmissionWebhook – IBM Cloud – Medium
    * nice diagram
    * [actual api](https://github.com/kubernetes/kubernetes/blob/v1.9.0/pkg/apis/admission/types.go)
* [github](https://github.com/morvencao/kube-mutating-webhook-tutorial)
    * mutating tutorial code
* [github](https://github.com/kubernetes/kubernetes/tree/release-1.9/test/images/webhook)
    * official test/sample code in 1.9 release
* [istio](https://github.com/istio/istio/tree/master/pilot/pkg/kube/inject)
    * where istio injects its own sidecar
* [banzaicloud](https://banzaicloud.com/blog/k8s-admission-webhooks/)
    * blog post about using admission hooks
* [kubewebhooklok](https://github.com/slok/kubewebhook)
    * Go framework that makes creating a hook easier
    * makes writing webhook very easy but ... the hard part is preparing certs
* API and CLI
* `v1beta.AdmissionReview`
* `v1beta1.AdmissionResponse`
* `admissionregistration.k8s.io/v1beta1`
* `kc delete mutatingWebhookConfiguration`

### Flow (from Banzai Cloud)
<img src="http://borlandc.pek3b.qingstor.com/k8s/k8s-webhooks.png" width=75%>

### Initialiser
* can't be used for `DELETE`
* [ibm](https://medium.com/ibm-cloud/kubernetes-initializers-deep-dive-and-tutorial-3bc416e4e13e)
* [ahmet](https://ahmet.im/blog/initializers/)


# Networking
* three networks
    * infra network that connects nodes
    * service network: pure virtual network, handled by firewall rules
    * pod network
* each pod has its own IP address
    * This is a balanced design between IP per host and IP per container
* no NAT allowed between containers or containers and node (minion)
* kubernetes has the concept of cloud provider, which handles
    * load balancing
    * routes
* in general, two ways of achieving connectivity
    * overlay
    * direct
* solutions include
    * flannel
    * calico
    * romana
    * weave
    * canal = flannel + calico
    * open vswitch
* [comparison](http://machinezone.github.io/research/networking-solutions-for-kubernetes/)
    * compares net host, ipvlan and flannel
    * a bit dated
* [google sheet](https://docs.google.com/spreadsheets/d/1qCOlor16Wp5mHd6MQxB5gUEQILnijyDLIExEpqmee2k/edit#gid=0)
    * large table with CNI plugins side by side
* [kubedex](https://kubedex.com/kubernetes-network-plugins/)
    * a lot of vendors uses Calico by default
* [tim hockin, ingress](https://speakerdeck.com/thockin/bringing-traffic-into-your-kubernetes-cluster)
    * **Bringing Traffic Into Your Kubernetes Cluster**
    * ingress is only one way
    * number of hops is important
    * avoid SNAT when possible
* [tim hockin, why](https://speakerdeck.com/thockin/kubernetes-and-networks-why-is-this-so-dang-hard)
    * **Kubernetes and Networks - why is this so dang hard?**
    * various different networking models

## CNI
* invoke:
    * runtime creates network namespace
    * runtime checks the `type` field in JSON file and invokes the right plugin
* a CNI plugin is responsible for:
    1. insert network interface into a network namespace (e.g. container)
    2. arrange things on the host (e.g. attach veth to a bridge)
    3. assign IP (invoking IPAM plugin)
* IPAM plugin is separate
    * [IPAM plugin code](https://github.com/containernetworking/plugins/tree/master/plugins/ipam)
    * dhcp, host-local and static
* each plugin is implemented by a binary
    * normally the plugin binaries are installed `/opt/cni/bin`
    * **NOTE** that these are plugin binaries, not daemon/controller binaries like `flanneld`
* `--network-plugin=cni`
* `/etc/cni/net.d` as conf directory
* [github](https://github.com/containernetworking/cni)
    * GitHub - containernetworking/cni: Container Network Interface - networking for Linux containers
* [plugins github](https://github.com/containernetworking/plugins)
    * GitHub - containernetworking/plugins: Some standard networking plugins, maintained by the CNI team.
    * `main` contains default plugins like bridge, macvlan, ipvlan, etc
    * `meta` contains flannel, calico, etc
* [actual spec](https://github.com/containernetworking/cni/blob/master/SPEC.md)
    * cni/SPEC.md at master · containernetworking/cni · GitHub
* [dasb](http://www.dasblinkenlichten.com/understanding-cni-container-networking-interface/)
    * Das Blinken Lichten &middot; Understanding CNI (Container Networking Interface)
* [dasb](http://www.dasblinkenlichten.com/using-cni-docker/)
    * Das Blinken Lichten &middot; Using CNI with Docker
* [altoros](https://www.altoros.com/blog/kubernetes-networking-writing-your-own-simple-cni-plug-in-with-bash/)
    * Kubernetes Networking: How to Write Your Own CNI Plug-in with Bash | Altoros
    * shell script for managing bridge, subnet, allocating new IP, etc
* plugin can have delegate
    * the flannel plugin delegates bridge creation and IPAM to the `bridge` plugin
* plugin can be chained
    * looks like it started with CNI spec 0.3.0
    * `plugins: [{type: calico}, {type: portMap}]`
    * also called config list
    * [karam, 2018](https://karampok.me/posts/chained-plugins-cni/)
         **CHAINING CNI PLUGINS**

### Plugins
* bridge
    * find the bridge (default to `cni0`)
    * connects both ends of veth
* macvlan
    * a virtual device enslaved to a physical device, e.g. `eth0`
    * WLAN device cannot be enslaved to
    * works with a IPAM plugin
    * supports a lot of different mode, defaults to `bridge`
        * not sure what the different modes are
* ipvlan
* ptp
    * point to point between container and host
* host-device
    * move an existing device into container netns
* loopback
    * creates the `lo` device in netns
* flannel
    * works with `flanneld`
    * delegates to `bridge` plugin
    * default `bridge` configuration is to use `host-local` IPAM

### IPAM Plugins
* host-local
    * [discussion on static IP](https://github.com/containernetworking/cni/issues/303)
* static
    * seems useless as it can only give on set of static IP
* DHCP

### Plugin API
* `ADD`
    * INPUT: network namespace, network configuration
* `DELETE`
* `VERSION`
* `GET`

### Flannel
* etcd backed overlay
* cross host shared routing table stored in etcd
* each node has its own subnet
* `flanneld`
    * manages the subnet
    * distribute IP address for each pod
* configuration exposed with `/run/flannel/subnet.env`
* on host
    * `cni0` is like docker bridge that all pods connects to
    * `flannel.1` is a virtual device that wraps all data in VXLAN (if
      necessary) and routes all data to `eth0` on the host 
* [laputa](https://blog.laputa.io/kubernetes-flannel-networking-6a1cb1f8ec7c)
    * very detailed explaination how flannel works
    * container's gateway is `cni0`, packets goes to `cni0` first (10.96.1.1/24)
    * routing rule forward the packet to `flannel.1` (10.96.1.0/16)
    * `flannel.1` is a TUN device, which is a kernel virtual L2 device
    * all incoming/outgoing packets gets forwarded to `flanneld`
    * `flanneld` knows how to forward/tunnel the packets to which hosts, as all `flanneld` are connected to `etcd` cluster where such information is stored
    * `etcdctl ls /coreos.com/network/subnets`
* [alicloud](https://github.com/coreos/flannel/blob/master/Documentation/alicloud-vpc-backend.md)
    * flannel alicloud VPC backend

### Calico
* Layer 3 model
* Uses BGP
* No NATting

### Weave
* Overlay networking
* Compatible with both libnetwork and k8s

### Canal
* canal = calico + flannel
* company behind it is called Tigera
* technically it's possible to combine networking from flannel and policy side
  from calico
* [news](https://www.projectcalico.org/canal-tigera/)

### kubenet plugin
* simple plugin implementation
* no cross-node networking by itself
* implements: `cbr0`

## DNS
* services
    * each normal service has an DNS entry like `foo`.
        * resolves to cluster IP of the service
    * headless service has an DNS entry like `foo`.
        * resolves to IPs from all end point that's associated with the service
        * client side round robin expected
    * FQDN is `service.namespace.svc.cluster.local`
        * `cluster.local` part can be configured with kubelet
* pod
    * each pod has DNS entry like `1-2-3-4.default.pod.cluster.local` where
      `1-2-3-4` is the IP of the POD
    * `spec.subDomain` can be used to specify subdomain, after which,
      `hostname.subdomain.ns.cluster.local` is in the DNS records
* each pod can have a `dnsPolicy` defined
    * `Default`: inherit configuration from node
    * `ClusterFirst`: queries are sent to `kube-dns` service
        * this is the default behavior
    * `ClusterFirstWithHostNet` ???
* deployed as an add-on
    * [github md](https://github.com/kubernetes/kubernetes/blob/master/cluster/addons/dns/README.md)
* `/etc/resolve.conf` adds a lot of search for k8s namespaces
    * `search default.svc.cluster.local svc.cluster.local cluster.local wise2c.com`
* actual records are stored in etcd for internal resolver to query through HTTP
* `dnsmasq` handles caching of records
* even if a pod is using host network, DNS resolving works as expected
* it is possible to setup sub domain servers and upstream servers
    * [here](https://kubernetes.io/docs/tasks/administer-cluster/dns-custom-nameservers/)
* [sysdig](https://sysdig.com/blog/understanding-how-kubernetes-services-dns-work/)
    * tracing DNS using sysdig
* trouble-shooting
    * `kubectl get pods --namespace=kube-system -l k8s-app=kube-dns`
    * `kubectl logs --namespace=kube-system $(kubectl get pods --namespace=kube-system -l k8s-app=kube-dns -o name) -c kubedns`
    * `kubectl logs --namespace=kube-system $(kubectl get pods --namespace=kube-system -l k8s-app=kube-dns -o name) -c dnsmasq`
    * `kubectl logs --namespace=kube-system $(kubectl get pods --namespace=kube-system -l k8s-app=kube-dns -o name) -c healthz`
* [spec](https://github.com/kubernetes/dns/blob/master/docs/specification.md)
    * kubernetes DNS spec
    * zone is like `cluster.local`
    * `dns-version TXT` stores schema version
    * `A` record for `svc.ns.zone`
    * for headless service, `svc.ns.zone` resolves to endpiont IP
* [internal](https://rsmitty.github.io/Manually-Checking-Out-KubeDNS/)
    * what's in the pod: etcd, kube2sky, skydns, exechealthz
    * where in etcd is the records

## Networking Policy
* introduced in 1.3, GA in 1.7
* ingress policy only as of now
* `apiVersion: networking.k8s.io/v1`
* `kind: NetworkPolicy`
* `spec.podSelector`
    * pod that's affected
    * empty means all
    * `matchLabels` or `matchExpressions[]`
* `spec.ingress[]`
    * empty means nothing is allowed
    * list of white listed items
    * `ingress[].from.podSelector`
    * `ingress[].from.nameSpaceSelector`
    * `ingress[].ports`
        * empty or missing means all ports, i.e. not restricted
        * otherwise white listing


# Storage
* in k8s' term, **persistent** disk
* currently support three types of storage
    * in tree
    * Flex
    * CSI
* supports:
    * docker volume
    * GCE disk
    * AWS EBS
    * NFS
    * gitrepo, clones a git repo
* supports for cloud storage is specified as `spec.volumes`
    * e.g `spec.volumes.gcePersistentDisk`
    * this implies that the core kubernetes code understands the syntax
    * so FlexVolume might be the only option when one wants to add customized volumes
* PV reclaim policy
    * Retain, where the volume is in a released state but the data is retained and can be recovered. 
    * Delete, where the volume is deleted.
* [faq](https://github.com/kubernetes/community/blob/master/sig-storage/volume-plugin-faq.md)
    * k8s volume plugin FAQ
    * three methods:
        0. in tree volume plugin
        0. out-of-tree FlexVolume driver
        0. out-of-tree CSI driver
* [sheng yang](https://rancher.com/blog/2018/2018-09-20-unexpected-kubernetes-part-1/?utm_campaign=Blog%202018&utm_content=77602215&utm_medium=social&utm_source=twitter)
    * rants about PV, PVC, StorageClass, etc by an Rancher engineer
    * special rants about `Volume` object
    * [part-2](https://rancher.com/blog/2018/2018-10-11-unexpected-kubernetes-part-2/)
    * verdict: use storage in the following order when possible:
        * use Volume when necessary (cm, secrete, etc)
        * use provisioner where can
* [software engineering daily, simsek](https://softwareengineeringdaily.com/2019/01/11/why-is-storage-on-kubernetes-is-so-hard/)
    * why is storage on kubernetes so hard
    * pretty decent summary of storage on kubernetes
    * CSI, rook, PV, PVC

## Volume types
* `emptyDir`
    * for scratch space
    * will be removed once pod is gone
    * use host storage by default, can be configured to use RAM
    * `sizeLimit` can be used to limit its size
* `hostPath`
    * similar to docker's `/hostpath:/containerpath`
    * given target will be created as an empty directory owned by root if it does not already exist.
    * ? What if it already exists?
    * data only writable by `root`
    * ??? remove once pod is gone?
* `nfs`
* `iscsi`
* `secret`
* `persistentVolumeClaim`
    * `spec.storageClassName` what type of storage to claim
* `gitRepo`
    * allow to specify git repo with commit hash
    * looks like this is not the [right way](https://github.com/kubernetes/kubernetes/issues/17676) and is deprecated

## PersistentVolume
* aka PV
* it's like a node, which means that it's a cluster resource provided by an
  admin
* **NOT** namespaced!!!
* procedure
    * create persistent volume `kubctl create -f`
    * create persistent volume claim, status of that volume changes to `BOUND`
    * create pod that uses the volume
* life-cycle
    * static volume: provisioned by admin and available all the time
    * dynamic volume: when `StorageClass` is defined
    * `volume.beta.kubernetes.io/storage-class: "example-nfs"`
* storage class
    * PVC can request for a certain **class** of storage. E.g. google
    * PVC class has to match PV class for it to bound
    * in this case, the storage can be automatically allocated from the vendor
    * `storageClassName`
    * default storage class:
        * `kubectl patch storageclass standard -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'`
* access mode
    * `ReadWriteOnce` single node only, `R+W`
    * `ReadWriteMany` many nodes, `R+W`
    * `ReadOnlyMany` many nodes, `R`
* local PV
    * GA in 1.14
    * doesn't not support dynamic provisioning
        * two options  rancher or OpenEBS
        * [rancher](https://github.com/rancher/local-path-provisioner)
    * [local PV, 2018](https://kubernetes.io/docs/concepts/storage/volumes/#local)
        * _The system is aware of the volume's node constraints by looking at the node affinity on the PersistentVolume._
        * _If a node becomes unhealthy, then the local volume becomes inaccessible by the pod._
    * [blog, 2018](https://kubernetes.io/blog/2018/04/13/local-persistent-volumes-beta/)
        * suitable for:
            * _Caching of datasets that can leverage data gravity for fast processing_
            * _Distributed storage systems that shard or replicate data across multiple nodes. Examples include distributed datastores like Cassandra, or distributed file systems like Gluster or Ceph._
            * i.e data loss is managable
    * [rancher, delete](https://github.com/rancher/local-path-provisioner#usage)
        * documentation from Rancher provisioner that proves that data is reserved cross pod re-creation


### Chapter 6 @@
<img src="http://borlandc.pek3b.qingstor.com/k8s/pvc-provisoner-chapter6.png" width=75%>

## Spec
* `spec.volumes`
    * `emptyDir`, `hostPath`, etc
* `spec.containers.volumeMounts`
    * `mountPath`: container path
    * `name`: which volume

## Snapshot
* only supported by
    * GCE
    * Portworx
    * NetApp

## FlexVolume
* [github md](https://github.com/kubernetes/community/blob/master/contributors/devel/flexvolume.md)
* installation is by copying binary into a specific path on node
    * `/usr/libexec/kubernetes/kubelet-plugins/volume/exec/<vendor~driver>/<driver>`
    * or it has to be `/driver/driver`
* alpha from 1.2, GA from 1.8
    * supposedly replaced by CSI but k8s will [continue supports it](https://github.com/kvaps/kube-loop-flexvolume)
* API are defined as argument to the binary `driver-exec <args>`. Return of the API
  should be in JSON format
    * `init`
    * `attach`
        * in: json option, node name
        * useful for remote volumes such as EBS
        * this is optional, return `Not supported` in status string
    * `mount`: Mount device mounts the device to a global path **on the host**
      which individual pods can then bind mount.
        * in: `mount_dir, mount device, json options`
    * `unmount`
    * `detach`
        * in: json option, node name
        * optional
* example are under `git://examples/volumes/flexvolume`
* [leebrigg](http://leebriggs.co.uk/blog/2017/03/12/kubernetes-flexvolumes.html)
    * nice introduction
* [rancher](https://github.com/rancher/rancher-flexvol)
* [cifs](https://github.com/fvigotti/cifs_k8s_plugin/blob/master/cifs.sh)

## Dynamic Provisioning
* [out of tree dynamic pv](https://github.com/kubernetes-incubator/external-storage)
    * [blog](http://blog.kubernetes.io/2016/10/dynamic-provisioning-and-storage-in-kubernetes.html)
    * storage class is global, not namespaced
    * PVC is namespaced
* objects involved
    * `StorageClass` defines a new storage class backed by code
        * `provisioner` has to match the actual POD envar for the handler to
          work
        * [code is here](https://github.com/kubernetes-incubator/external-storage/blob/master/nfs-client/cmd/nfs-client-provisioner/provisioner.go)
    * `PersistenVolumeClaim`
        * with `volume.beta.kubernetes.io/storage-class`
        * triggers the Pod to dynamically create a PVC

### Internal
* a controller is implemented that listens on volume creation and dynamically creates `v1.PersistentVolume` objects that will be handled by k8s
* it creats a provision controller and run it non stop

## CSI
* Container Storage Interface
* an initiative to unify the storage interface of Container Orchestrator Systems (COs) like Kubernetes, Mesos, Docker swarm, cloud foundry, etc. combined with storage vendors like Ceph, Portworx, NetApp etc
* cross orchestration platform
* **Bugs in volume plugins can crash critical Kubernetes components, instead of just the plugin.**
    * !!!
* [spec 1.0](https://github.com/container-storage-interface/spec/releases/tag/v1.0.0)
    * [markdown](https://github.com/container-storage-interface/spec/blob/master/spec.md)
* [blog, k8s](https://kubernetes.io/blog/2019/01/15/container-storage-interface-ga/)
    * **Container Storage Interface (CSI) for Kubernetes GA**
* [medium, google-cloud](https://medium.com/google-cloud/understanding-the-container-storage-interface-csi-ddbeb966a3b)
    * **Understanding the Container Storage Interface (CSI)**
    * nice colorful architecturual diagrams
* [pdf, yu jie](https://schd.ws/hosted_files/kccnceu18/fb/CloudNativeCon%20EU%202018%20CSI%20Jie%20Yu.pdf)
* [fatih, how-to](https://arslan.io/2018/06/21/how-to-write-a-container-storage-interface-csi-plugin/)
    * **How to write a Container Storage Interface (CSI) plugin**
    * all functions have to be idempotent
* [driver, github](https://github.com/kubernetes-csi/drivers)
    * https://github.com/kubernetes-csi/drivers
* [object store, appliance](https://www.datasciencecentral.com/profiles/blogs/you-can-t-containerize-an-appliance-why-kubernetes-and-high)
    * **You can't containerize an appliance: why Kubernetes and high performance object storage are tech's new building blocks.**
    * _There is not a CSI for object storage. It doesn’t need it._
    * _If you run an appliance today, you need to start making the change to software defined storage (object store)_

### Arch
<img src="http://borlandc.pek3b.qingstor.com/k8s/csi-arch-1.png" width=75%>

### API
* gRPC
* `service Identity`
    * both node and controller plugin have to implement this
    * `GetPluginInfo()`
    * `GetPluginCapabilities()`
    * `Probe()`
* `service Controller`
    * controller plugin must implement this
    * cloud providers has to implement this
    * `CreateVolume()`
    * `DeleteVolume()`
    * `ControllerPublishVolume()`
    * `ControllerUnpublishVolume()`
    * `ValidateVolumeCapabilities()`
    * `ListVolumes()`
    * `GetCapacities()`
    * `ControllerGetCapabilities()`
* `service Node`
    * node plugin must implement  this
    * `NodeStageVolume()`
    * `NodeUnstageVolume()`
    * `NodePublishVolume()`
    * `NodeUnpublishVolume()`
    * `NodeGetId()`
    * `NodeGetCapabilities()`


# API Authentication and Authorization
* API requests are tied to a user (see below) or executed anonymously
* 2 kinds of user: normal user and service account. service account is managed
  by kubernetes, normal user is not
* ways to connect to an API server
    * client certificats
    * bearer token
    * authentication proxy
    * HTTP basic auth
* Authz
    * node
    * APAC
    * RBAC
    * Webhook

## Client Certificate
so client cert is simply a PKI client certification signed by Kubernetes API server, then encoded into kubeconfig file as base64
1. create private key and CSR
    * `openssl genrsa -out dave.key 4096`
1. create and approve CSR
    * `kind: CertificateSigningRequest`
    * `kubectl certificate approve mycsr`
    * `openssl x509 -in ./dave.crt -noout -text`
1. use it in kubeconfig


## Service Account
* injects auth info into pods to talk to kubernetes services like the apiserver
    * `spec.serviceAccountName` in pod spec
* this is a namespaced resource
* as oppose to user account that's for humans
* when no service account is specified for a Pod, it'll be default
* default service account is injected into `/var/run/secrets/kubernetes.io/serviceaccount`
    * namespace
    * `ca.crt` (the global root certificate), allows secure communication with API server
    * token, says who you are and what you can do

### Nice Picture @@
<img src="http://borlandc.pek3b.qingstor.com/k8s/k8s-service-account.png" width=75%>

## RBAC
* role based access control
* introduced in 1.6 as beta
* apiserver needs to start with `--authorization-mode=RBAC`
* 4 kinds of object defined
    * Role
    * ClusterRole
    * RoleBinding
    * ClusterRoleBinding
* a **Role** is a collection of permissions. 
    * by default a Role is bound to a namespace
    * there is **ClusterRole** that applies across the cluter
* a **RoleBinding** binds a role to a **subject**
    * subject can be
        - user
        - group
        - service account
    * binding can be namespaced or cluster level across namespaces
* CLI
    * `kubectl get clusterroles --namespace=kube-system`
* [official blog, 2017](http://blog.kubernetes.io/2017/04/rbac-support-in-kubernetes.html)
    * **RBAC Support in Kubernetes**
* [rancher, group, 2017, 2019](https://rancher.com/understanding-kubernetes-rbac)
    * **Understanding Kubernetes RBAC**
    * _Group membership is only a string value, so the authentication component must set this string correctly. Kubernetes will only check for the presence of the string; it trusts the authentication provider._
* [dex, group](https://medium.com/preply-engineering/k8s-auth-a81f59d4dff6)
    * **Kubernetes authentication via GitHub OAuth and Dex**
    * _Unfortunately, Dex can’t handle groups with Google OIDC_


## OIDC Plugin (Proxy)
* id issued by 3rd party


### Dex
* OIDC and OAuth 2.0 Provider
    * AuthN
* came from CoreOS, independent after RedHat
* stateless
* [dex, k8s](https://github.com/dexidp/dex/blob/master/Documentation/kubernetes.md)
    * Kubernetes authentication through dex

## Links
* [k8s auth](https://kubernetes.io/docs/admin/authentication/)
* [rbac, banzaicloud](https://banzaicloud.com/blog/k8s-rbac/)
    * mainly talks about LDAP RBAC integration but has nice explannation of authenticating with API server
* [official](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
* [slides, hard](https://www.slideshare.net/IhorBorodin/diy-kubernetes-identity-provider-the-hard-way-with-dex-and-ldap-v2)
    * **DIY Kubernetes identity provider. The Hard Way with Dex and LDAP. v2**
    * talks about why choose LDAP over SAML, Google ID, github
        * good and bad about LDAP


# Resource Definition File
* YAML file that presents a spec for a resource
    * can also be JSON
* Sections
    * `apiVersion`
    * `kind`
    * `metadata`
    * `spec`
* **NOTE**: it's not possible to use environment variable in spec file


# kubectl
* kubectl supports one version forward and backward skew
* looks for `$HOME/.kube/config` file for configuration
    * can also be specified with `--kubeconfig` flag
* `export KUBERNETES_MASTER=http://host01:8080`
    * defines master to communicate with
* `kubectl get pod pod1`
* `kubectl get pods`
* `kubectl get pod -l run=my-nginx`
    * get pod with specific label
* `kubectl get deployments`
* `kubectl config use-context xxx`
    * swtich context (environment)
* `kubectl run my-web --image=nginx --port=80`
    * creates a **deployment** object
* `kubectl expose deployment my-web --target-port=80 --type=NodePort`
    * creates a service that exposes a deployment
    * allows external access through `NodePort`
* `kubectl scale deployment hello-node --replicas=4`
* `kubectl get svc`
    * list services
* `kubectrl create -f storage-memory.yaml`
    * create pod, namespace etc
* `kubectl create namespace staging`
    * create new namespace
* `kubectl exec foo-37kj5 -i -t -- sh`
    * like `docker exec`
* `kubectl exec -it two-containers -c nginx-container -- /bin/bash`
    * specifies pod **and** container
* `kubectl logs foo-37kj5`
    * check log from a pod
    * `-c` to specify a container
* `kubectl get pod nginx -o go-template='{{.status.podIP}}'`
    * get IP of pod named `nginx`
* `kubectl describe namespace/test`
    * describe stuff
    * other stuff maybe `rc/busybox-ns`
    * `kubectl describe service ghost`
* `kubectl set image deployment/hello-node hello-node=gcr.io/$PROJECT_ID/hello-node:v2`
    * upgrade a service by setting a new version of image
    * won't work if the image name stays the same, e.g. `:latest`
* `kubectl delete pod nginx`
    * `kubectl delete pods <pod> --grace-period=0 --force` to force it
* `kubectl delete rc nginx`
    * delete replication controller
* `kubectl delete svc nginx`
    * delete service
* `kubectl logs -c container pod`
* `kubectl config use-context k3`
    * switch cluster
* `kubectl cordon $NODENAME`
    * make node unschedlable
* `kubectl get nodes -o jsonpath='{range.items[*].metadata}{.name} {end}'`
* `kubectl get pod liang-web-3685169472-vbxh6 -o jsonpath='{.status.podIP}'`
    * specific information retrieval
* `kubectl patch node k8s-node-1 -p '{"spec":{"unschedulable":true}}`
    * patch a node so that it'll not be scheduled on
    * `kubectl patch (-f FILENAME TYPENAME) -p PATCH`
* `kubectl edit deploy/orchestration`
    * fire up editor and edit YAML definition of a deployment
* `kubectl convert -f pod.yaml --output-version v1`
    * convert/migrate file between API version
    * can be done locally or through API server
    * schema are stored under `$HOME/.kube/schema/`
* `kubectl explain --recursive pod` 
    * describes what a pod definition is
* `kubectl api-resources`
    * list all available resources
* `kubectl get pods --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace,QOS-CLASS:.status.qosClass`
    * customized field
* `kubectl get rs,secrets -o json --namespace old | jq '.items[].metadata.namespace = "new"' | kubectl create -f  -`
* `kubectl get node -v8`
    * very verbose, good for debugging
* `kubectl -n istio-system port-forward $(kubectl -n istio-system get pod -l app=grafana -o jsonpath='{.items[0].metadata.name}') 3000:3000`
    * `port-forward` forward one or more local ports to a pod
* `kubectl cordon`
    * make the node unschedulable
    * same as `node.Spec.Unschedulable=true`
* `kubectl drain`
    * first it _cordon_ the node
    * then does _evict_ of pods
        * > 1.7
    * pods can be filtered, e.g. `--ignore-daemonsets`
    * [banzaicloud](https://banzaicloud.com/blog/drain/)
* `kubectl get secret gitlab-registry --namespace=revsys-com --export -o yaml |\ kubectl apply --namespace=devspectrum-dev -f -`
    * copy objects betwen namespaces
* `kubectl get --raw=/apis`
    * get raw REST API resonse
* `kubectl --v=9 get pod rbd-provisioner-b8ffcb96d-62x9f`
    * `--v=9` asks for extra debug output
    * `kubectl` actually uses `curl` command for calling REST HTTP server
    * `curl -k -v -XGET  -H "Accept: application/json;as=Table;v=v1;g=meta.k8s.io,application/json;as=Table;v=v1beta1;g=meta.k8s.io,application/json" -H "User-Agent: kubectl/v1.19.0 (darwin/amd64) kubernetes/e199641" 'https://139.198.123.110:6443/api/v1/namespaces/default/pods/rbd-provisioner-b8ffcb96d-62x9f'`
* `kubectl get po -n soltysh --as=system:admin`
    * impersonate, need to turn on role
    * `kubectl create clusterrolebinding impersonator-nonadmin --clusterrole=impersonator --user=nonadmin`
* `kubectl alpha debug -n n1 www-5d8ccf558f-7j2tm --image=busybox`
    * run a debug sidecar
    * server has to enable this

## Troubleshooting
* `kubectl get cs`
    * get componentstatuses for master: scheduler, controller manager, etcd
* `kubectl top`
    * requires heapster to work

## Security
* `kubectl certificate approve`
* `kubectl certificate deny`

## Configuration
* `$HOME/.kube/config` includes configuration for all contexts
* it has several sections
    * cluster
    * context
    * user
* to get a new cluster into the `config` file, one has to merge content of `admin.conf`
  into it
* `kubectl --kubeconfig ./admin.conf get nodes`
    * config file is generated by `kubeadm` in `/etc/kubernetes/admin/.conf`
* use the following combination
    * kube-ps1 + kubectx + kubens!!!
* [medium, master](https://medium.com/@ahmetb/mastering-kubeconfig-4e447aa32c75)
    * merge, extract, direct use of username, password

### CLI
     # Save certificates and the key as files
     $ kubectl config set-cluster default-cluster --server=https://45.32.47.214  --certificate-authority=${CA_CERT}
     $ kubectl config set-credentials default-admin --certificate-authority=${CA_CERT} --client-key=${ADMIN_KEY} --client-certificate=${ADMIN_CERT}
     $ kubectl config set-context default-system --cluster=default-cluster --user=default-admin
     $ kubectl config use-context default-system

## Plugins
* loaded from predefined directories:
    * `$HOME/.kube/plugin`
    * e.g. `.kube/plugin/hello/plugin.yaml` has to follow this naming
* `kubectl plugin hello` runs the plugin

## Links
* [kubectl man pages](https://www.mankier.com/package/kubernetes-client)
* [installation](https://kubernetes.io/docs/tasks/tools/install-kubectl/#download-as-part-of-the-google-cloud-sdk)
    * with manual download instruction


# YAML

## Meta
* `apiVersion`
* `kind`
    * pod
    * rc
    * Deployment
    * Service
    * etc
* `label`

## Spec
* `containers`: type list
    * `image`
    * `name`
    * `ports`
        * has `name`!!!

## Sample

    apiVersion: apps/v1beta1
    kind: Deployment
    metadata:
      name: web-deployment
    spec:
      replicas: 2
      template:
        metadata:
          labels:
            name: web
        spec:
          containers:
          - image: gcr.io/<YOUR-PROJECT-ID>/myapp
            name: web
            ports:
            - name: http-server
              containerPort: 3000


# API

## Overview
* resource catagory
    * workloads
    * discovery & LB
    * config and storage
    * cluster
    * metadata
* resource objects
    * spec
    * status
    * meta
* resource operation
    * create
    * read
    * delete
    * rollback
* workloads
    * deployments: for stateless apps
    * statefullset: for persistent apps
    * jobs: run-to-completion apps

## Convention
* Kind
* Resource
* API Group
    * group/version

## Links
* [1.6 pod spec](https://kubernetes.io/docs/api-reference/v1.6/#podspec-v1-core)
* [1.6 container](https://kubernetes.io/docs/api-reference/v1.6/#container-v1-core)
* [1.6 deployment](https://kubernetes.io/docs/api-reference/v1.6/#deployment-v1beta1-apps)
* [1.6 service](https://kubernetes.io/docs/api-reference/v1.6/#service-v1-core)
* [openshift 3.7](https://docs.openshift.com/container-platform/3.7/rest_api/index.html)
    * REST API reference
    * not directly k8s but should be the same

## Proxy
* `kubectl proxy -p 8001`
    * generates a proxy server that can be used as REST API server
    * handles authentication
    * `curl http://localhost:8001/api/v1/namespaces/default/pods`


# UI / Dashboard
* [kube-web-view](https://codeberg.org/hjacobs/kube-web-view/)
    * [live demo](https://kube-web-view.demo.j-serv.de/clusters/local/nodes)
* [k8dash](https://github.com/herbrandson/k8dash)
* [kubernator](https://github.com/smpio/kubernator)
* [dashboard](https://github.com/kubernetes/dashboard)
* [kube-ops-view](https://github.com/hjacobs/kube-ops-view)
    * ops oriented, with node, cpu, ram as center view
    * python, js
* [kube-resource-report](https://github.com/hjacobs/kube-resource-report/)
    * node cost for cloud resources
    * Python, html (static site)
* [octant, vmware](https://github.com/vmware/octant)
    * ...
* [comp, blog](https://srcco.de/posts/kubernetes-web-uis-in-2019.html)


# Installation
* [get](https://get.k8s.io)
* [binary](https://github.com/kubernetes/kubernetes/releases/latest)
* each node runs:
    * docker
    * kubelet
    * kube-proxy (not strictly required on a master node)
* kubernetes services, each run as a pod on the master node
    * apiserver
    * controller manager
    * scheduler
    * all runs the same `hyperkube` binary with different swtich
        * `hyperkube` is like `busybox`

## kubernetes the hard way
* download cfssl and cfssljson
* prepare compute instances (gcloud specific)
* create CA 
    * `cfssl gencert -initca ca-csr.json | cfssljson -bare ca`
    * creates `ca.pem` and `ca-key.pem`
* create admin client certificate
    * `cfssl gencert -ca=xxx -ca-key=xxx -config=xxx -profile=xxx admin-csr.json | cfssljson -bare admin`
    * ca and ca-key is generated in previous step
    * creates `admin.pem` and `admin-key.pem`
* likely, create api server certificate
* likely, create kubelet client certificate
* distribute certification
    * copy `ca.pem` and instance certificates to each minion
    * copy `ca.pem`, `ca-key.pem` and api server certs to each controller
* configure encryption configuration
* bring up etcd
    * `sudo cp ca.pem kubernetes-key.pem kubernetes.pem /etc/etcd/`
    * configure systemd etcd service
* bring up kubernetes control plane
    * `sudo mv ca.pem ca-key.pem kubernetes-key.pem kubernetes.pem encryption-config.yaml /var/lib/kubernetes/`
        * CA key pair
        * api server key pair
        * encryption config
    * configure apiserver with systemd
    * configure controller manager
    * `kubectl get componentstatuses`
* bring up node
    * download cni binary
    * download crio binary
    * configure network
    * configure kubelet
    * configure kubeproxy
* deploy DNS add-on
* [link](https://github.com/kelseyhightower/kubernetes-the-hard-way)

## minikube
* `brew install Caskroom/cask/minikube`
* `minikube start`
* `minikube dashboard`

## kubeadm
* automated installation tool, handles
    * preflight check
    * PKI creation
    * generates token used for node to join
    * manages kubelet running options
* by default, images are pulled from gcr.io/google_containers
    * apiserver
    * controller-manager
    * scheduler
    * proxy
    * etcd
    * pause
    * dns-sidecar
    * kube-dns
    * dns-masq
* installs DNS add-on
    * can pick from default and coredns
* when `KUBE_HYPERKUBE_IMAGE` is defined, a single hyperkube image is used
* configuration can be done through file
* [reference](https://kubernetes.io/docs/admin/kubeadm/)
* [ntp](https://github.com/kubernetes/kubernetes/issues/42791)
    * ntp should be installed on all nodes

### Install
* normally with `apt` or `yum`

### Configurable
* `--pod-network-cidr`
* etcd server
    * either through image envar
    * or config file
* repo prefix
    * `KUBE_REPO_PREFIX`
    * when specified, `--pod-infra-container-image` has to be change too

### Each host
* docker
* kubelet
* kubectl (master only)
* kubeadm
* cni

### Steps
1. install docker
2. install kubernetes packages (apt)
    * kubelet
    * kubectl
    * kubeadm
3. disable SELinux
4. on master, do
    * `kubeadmin init --api-advertise-addresses=<host_ip> --use-kubernetes-version=v1.5.3 --pod-network-cidr=10.244.0.0/16`
    * `kubectl apply -f kube-flannel.yml`
    * normally kubernets' images are self contained. but if there is mismatch
      between versions, do `export XXXX_IAMGE=bla`
5. on each node
    * flannel images has to be present on each node
    * `kubeadm join --token=d562d2.bf3721e0655d4f12 192.168.0.177`
6. `kubctl get nodes` on master should show all nodes

### Internal 
* with control plane, it uses `kubelet` to managed components like `etcd, apiserver` etc
    * `systemd` runs `kubelet` as a normal process
    * `kubelet --pod-manifest-path /etc/kubernetes/manifests` starts everything
      in that directory as pods
        - files in that folder are simply kubernetes YAML spec that `kubelet`
          understands
        - see `/etc/systemd/system/kubelet.service.d/10-kubeadm.conf`
* [how does it work](https://www.ianlewis.org/en/how-kubeadm-initializes-your-kubernetes-master)

### OKDC
* [dockone, okdc](http://www.dockone.io/article/2296)
* no need to install docker
* install lsb
* make sure /etc/hosts has all the nodes
* `setenforce 0`
* on master
    * just run the script
* on node
    * at the end of the master run it actually gives command to run on the node


### commands

    apt-get update
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
    cat <<EOF > /etc/apt/sources.list.d/kubernetes.list
       deb http://apt.kubernetes.io/ kubernetes-xenial main
       EOF
    apt-get update
    apt-get install -y docker.io
    apt-get install -y kubelet kubeadm kubectl kubernetes-cni
    service kubelet stop
    service kubelet start
    kubeadm init --use-kubernetes-version v1.4.1



# Security
* having SSH account into container is bad practice
* [kubeaudit](https://github.com/Shopify/kubeaudit)
    * automatically audit security in a kubernetes cluster

## OPA (Open Policy Agent)
* not a kubernetes specific thing but can be used with k8s admission control
* [magalix](https://www.magalix.com/blog/introducing-policy-as-code-the-open-policy-agent-opa)


# Monitoring
* 4 level of monitoring
    * host
    * containers
    * kubernetes
    * applications
* cAdvisor, kubelet -> heapster -> backend
    * backend supported:
        * influxdb
        * opentsdb
        * kafka
        * many others
    * heapster run as a pod in the cluster

## cAdvisor
* runs as part of kubelet

## Links
* [datadog](https://www.datadoghq.com/blog/monitoring-kubernetes-era/)
    * However, as explained in the first section of this post, to track memory
      and CPU usage you should favor the metrics reported by your container
      technology, such as Docker, rather than the Kubernetes statistics reported
      by Heapster.


# Container Runtime
* [containerd blog](https://kubernetes.io/blog/2018/05/24/kubernetes-containerd-integration-goes-ga/)
    * containerd integration goes GA

## Arch
<img src="http://borlandc.pek3b.qingstor.com/container/cri-containerd.jpg">

## CRI
* container runtime interface for kubernetes
* parallel to CNI, CSI, etc
* implementations
    * containerd (cri, cri-containerd)
    * CRI-O: [OCI](https://www.opencontainers.org) conformant, used to be called OCID, RedHat, etc
    * frakti (hyper.sh)
* [openstack, PDF, PPT](https://www.openstack.org/assets/presentation-media/hyper-kata-frakti-cri2.pdf)
    * topic is Frakti, but has a good bit of information on CRI, with history,
      landscape, etc
    * kata
* [suse, cri-o, kubic](https://kubic.opensuse.org/blog/2018-09-17-crio-default/)
    * **CRI-O is now our default container runtime interface**
* [infoq](https://www.infoq.com/news/2019/05/cri-o-kubernetes-runtime/)
    * **CRI-O: An Open Source Container Runtime for Kubernetes**

### Spec
* Sandbox
    * `Create`
    * `Delete`
    * `List`
* Container
    * `Create`
    * `Start`
    * `Exec`
* Image
    * `Pull`
    * `List`

## CRI-O
* [.io](https://cri-o.io/)
* conmon handles monitoring, including logging
* podman is like docker CLI
* docker and podman can co-exist on the same host
* _CRI-O 1.13 shipping with OpenShift 4.1 as the only supported engine_

## containerd
* container runtime
* as a daemon
* responsible for
    * image transfer
    * container execution
    * network attachment
* full OCI support
* depends on runc
* stuff are namespaced
    * within kubernetes, `k8s.io` is the default namespace
* [spun out of docker](https://blog.docker.com/2016/12/introducing-containerd/)
    * into CNCF
* [github](https://github.com/containerd)
* [cri plugin ](https://github.com/containerd/cri)
    * [crictl](https://github.com/containerd/cri/blob/master/docs/crictl.md)
    * [sig crictl](https://github.com/kubernetes-sigs/cri-tools/blob/master/docs/crictl.md)
* [ctr cli reference](https://github.com/projectatomic/containerd/blob/master/docs/cli.md)

## rurnc
* `runc` is a CLI tool for spawning and running containers according to the OCI specification.


# High Availability
* [keith](http://www.fawwheel.com/keithtt/p/6649995.html)
    * external etcd
    * master each has a keep alived
    * use kubeadm for installation
    * pull images from a pre-defined HTTP server
    * single BASH script for master and node
* [official](https://kubernetes.io/docs/admin/high-availability/)
    * mentioned `monit` for monitoring k8s and docker daemon
    * talked about etcd
    * api is replicated and load-balanced
    * scheduler and controller-manager which actually modifies the cluster state
      uses the `--leader-elect` flag to make sure only one is doing the work 
      at a time
    * see **ha with ansible** in the link section
* [kargo](https://github.com/kubernetes-incubator/kargo)
* [kubeform](https://github.com/Capgemini/kubeform)
* [sumit/podmaster](https://sumitkgaur.wordpress.com/2016/07/30/kubernetes-truely-ha-cluster/)
    * works together with etcd
    * make sure that only the leader runs scheduler
    * generic solution but mostly works with kubernetes



## Unsupported syntax
* `build` command
    * `dockerfile`
* `cap_add`

## Links
* [k8s blog](http://blog.kubernetes.io/2016/11/kompose-tool-go-from-docker-compose-to-kubernetes.html)
    * introduction article
* [io](http://kompose.io/)
    * official website
    * includes an architecture explanation that looks like the translator
* [conversion](http://kompose.io/conversion/)
    * list of compose definitions and how it gets converted


# Internal
* etcd is used for data storage and implementation of **watch** mechanism
* only the API server access the etcd directly

## kubelet
* it finds pods to run from the API server
* it runs an internal HTTP server on port 10255
    * [what is](http://kamalmarhubi.com/blog/2015/08/27/what-even-is-a-kubelet/)
    * provides health check `/healtz`
    * `/pods` for pods running on the node
    * `/spec` for the spec of the node
* `./kubelet --api-servers=http://master:8080`
* `kubelet --cluster-dns`
    * specify cluster DNS server
    * it gets inserted into `/etc/resolv.conf` when DNS policy is `clusterFirst`

## scheduler
* runs on master
* watches API server for unbound pod and assign it to a node
* `./kube-scheduler --master=http://localhost:8080`
* it is possible to run customized scheduler
    * [howto](https://kubernetes.io/docs/tasks/administer-cluster/configure-multiple-schedulers/)
    * [ibm](https://sysdig.com/blog/kubernetes-scheduler/)

## controller manager
* watches the shared state of the cluster through the apiserver and makes
  changes attempting to move the current state towards the desired state 

## Pod creation sequence
<img src="https://cdn-images-1.medium.com/max/1600/1*WDJmiyarVfcsDp6X1-lLFQ.png" width=75%>

## Links
* [what even is a kubelet](http://kamalmarhubi.com/blog/2015/08/27/what-even-is-a-kubelet/)


# Troubleshooting
* `journalctl -r -u kubelet`
* `kubectl get events -w`
    * `-w` for watch


# Extending
* [itnext](https://itnext.io/comparing-kubernetes-api-extension-mechanisms-of-custom-resource-definition-and-aggregated-api-64f4ca6d0966)
    * patterns api extension mechanism
* `kubectl get apiservice`
    * list current API names

## CRD/TPR
* [task](https://kubernetes.io/docs/tasks/access-kubernetes-api/extend-api-custom-resource-definitions/)
* **primary** API extension mechanism
* looks like it doesn't support versioning [yet](https://github.com/kubernetes/features/issues/544)

## API Aggregation
* [incubator doc](https://github.com/kubernetes-incubator/apiserver-builder/blob/master/docs/concepts/aggregation.md)
* full power of customization
* require etc storage

## Custom Sub resource
* a sub resource can be on a native or custom Kind
    * An example of a custom sub-resource can be http_requests_total defined on a Pod will allow you to find out the number of HTTP requests received by that Pod.

## Admission Webhook
* [admission webhook](https://github.com/kubernetes/features/issues/492)


# Operator
* k8s native way to run stateful application
* basic work flow is:
    * observe if the cluster has the right size
    * reconcile
    * rebalance data
* in a nutshell
    * reponsed to events
        * created
        * updated
        * deleted
    * try to reconcile
* operator SDK
    * has CLI: `operator-sdk`
    * `$ operator-sdk new <operator-project-name> --api-version=<your-api-group>/<version> --kind=<custom-resource-kind>`
    * `operator-sdk generate k8s`
    * `operator-sdk build <docker-image>`
* [banzaicloud](https://banzaicloud.com/blog/operator-sdk/)
    * a complete guide to kubernetes operator SDK
    * how to use the operator SDK
        0. Create a new operator project
        0. Define the Kubernetes resources to watch
        0. Define the operator logic in a designated handler
        0. Update and generate code for custom resources
        0. Build and generate the operator deployment manifests
        0. Deploy the operator
        0. Create custom resources
* [darren, newstack](https://thenewstack.io/the-new-stack-context-kubernetes-moves-to-the-edge/)
    * podcast from NewStack with Darren
    * probably because of [this](https://twitter.com/ibuildthecloud/status/1295810776179961856?utm_source=thenewstack&utm_medium=website&utm_campaign=platform)

## Arch
<img src="https://blog.couchbase.com/wp-content/uploads/2018/03/Picture1-768x480.png">

## Links
* [python, operator](https://github.com/zalando-incubator/kopf)
    * kopf, from zalando
    * A Python framework to write Kubernetes operators in just few lines of code. https://kopf.readthedocs.io
* [youtube, hard](https://www.youtube.com/watch?v=wMqzAOp15wo)
    * **Writing a Kubernetes Operator: the Hard Parts - Sebastien Guilloux, Elastic**
    * [schedule, pdf](https://kccncna19.sched.com/event/UaeV)
    * operator lives into past (api server client uses a cached reader)
    * optimistic concurrency:
        * resource name
        * resource version
        * uid: on deletion


# Windows
* see dotnet.md


# VM, Virtualised Hardware

## Frakti
* based on Hyper
* requires 
* [youtube](https://www.youtube.com/watch?v=mBJ0tfLPyXg)
    * [google drive](https://drive.google.com/file/d/0B6uGv-NC7DxDSmREaUhEdXl4NGM/view)
        * companion slides

## kubevirt
* implemented as a entirely new `kind` CRD
* still needs PVC
* [blog](https://kubernetes.io/blog/2018/05/22/getting-to-know-kubevirt/)
    * getting to know kubevirt

## virtlet
* from Mirantis
* implemented as CRI
    * daemonset is run on host where VM can be scheduled onto and handled separately from normal pods
* runs arbitary QCOW2 images
    * image names are translated from `virtlet.cloud/` to a real image address
    * so probably it still needs PVs
* [mirantis, introduction](https://www.mirantis.com/blog/virtlet-vms-containers-opencontrail-network-kubernetes-nfv/)
* [kubevirt vs virtlet](https://www.mirantis.com/blog/kubevirt-vs-virtlet-comparison-better/)
    * kubevirt vs virtlet
* [dockerhub](https://hub.docker.com/r/mirantis/virtlet/)
    * docker hub page has some nice info
* [persistent](https://docs.virtlet.cloud/reference/volumes/#persistent-root-filesystem)
    * persistent root filesystem
    * [example](https://github.com/Mirantis/virtlet/tree/master/examples#using-the-persistent-root-filesystem)

### Arch
<img src="http://borlandc.pek3b.qingstor.com/k8s/virtletarchitecture.png" width=75%>

## kata container
...


# Distributions
* [typhoon](https://github.com/poseidon/typhoon)
    * minimal and free


# Questions
* With a `hostPath` volume, will it be removed when the POD dies?
    * no. looks like the stuff is retained


# Links
* [intro](https://github.com/rosskukulinski/docker-philly)
* [minikube](https://github.com/kubernetes/minikube)
    * run k8s cluster on a single host
* [why kubernetes has won](http://www.infoworld.com/article/3118345/cloud-computing/why-kubernetes-is-winning-the-container-war.html)
* [kubernetes api](http://www.slideshare.net/sttts/an-introduction-to-the-kubernetes-api-56804279?utm_source=slideshow&utm_medium=ssemail&utm_campaign=download_notification)
    * explaine pods as docker commands, ipc, net, etc
* [V1 API](https://kubernetes.io/docs/api-reference/v1/definitions/)
    * official API doc for V1
* [ringstack](https://blog.risingstack.com/moving-node-js-from-paas-to-kubernetes-tutorial/)
    * moving node js to k8s
* [walkthrough](http://kubernetes.io/docs/user-guide/walkthrough/)
    * official tutorial
* [awesome](https://www.gitbook.com/book/ramitsurana/awesome-kubernetes/details)
    * git book
* [cheatsheet](http://k8s.info/cs.html)
* [official cheatsheet](https://kubernetes.io/docs/user-guide/kubectl-cheatsheet/)
    * from `kubernetes.io`
* [marantis](https://www.mirantis.com/blog/introduction-to-yaml-creating-a-kubernetes-deployment/)
    * introduction
* [5pi](http://5pi.de/2016/11/20/15-producation-grade-kubernetes-cluster/)
    * lengthy article on setting up production ready cluster
* [from scratch](https://kubernetes.io/docs/getting-started-guides/scratch/)
* [cheap way](https://medium.com/@zwischenzugs/learn-kubernetes-the-hard-way-the-easy-and-cheap-way-6f82b665ccd9)
* [kube news](http://kube.news/)
* [kompose](http://kompose.io/)
    * convert, deploy docker compose stacks into k8s
* [rootsong](http://rootsongjc.github.io/projects/kubernetes-installation-document/?from=timeline&isappinstalled=0)
    * 这可能是目前为止最详细的kubernetes安装文档了。
    * [markdown](https://github.com/opsnull/follow-me-install-kubernetes-cluster)
* [ubuntu](https://www.ubuntu.com/containers/kubernetes)
    * Ubuntu Kubernetes distribution
    * supports local and remote cloud
* [HA with ansible](https://github.com/pawankkamboj/HA-kubernetes-ansible)
    * HA k8s with Ansible
* [python API](https://github.com/kubernetes-incubator/client-python)
* [marantis](https://www.mirantis.com/blog/kubernetes-replication-controller-replica-set-and-deployments-understanding-replication-options/)
    * RC, RS and Deployments
* [demystify](https://www.slideshare.net/WorksApplications/demystifying-kubernetes)
    * demystify kubernetes from slideshare
    * pretty detailed, ground-up explanation of kubernetes
* [qihu360](https://addops.cn/post/kubernetes-deployment-fileds.html)
    * what can goes into deployment object
* [tryk8s](https://tryk8s.com)
    * free k8s cluster to play with
    * login with github account
* [service lb](https://github.com/kubernetes/contrib/tree/master/service-loadbalancer)
    * provide loadbalancer service for bare metal
* [jazz improve](https://blog.heptio.com/core-kubernetes-jazz-improv-over-orchestration-a7903ea92ca)
    * depth first article from CEO of heptio
* [coreos deploy master](https://coreos.com/kubernetes/docs/latest/deploy-master.html)
* [rbac](http://www.opcito.com/secure-kubernetes-clusters-rbac/)
    * securing kubernetes cluter with RBAC
    * compares to ABAC (attribute based access control)
        * ABAC is deprecated
* [app-controller](https://github.com/Mirantis/k8s-AppController)
    * manages dependency
    * seems to create new kubernetes objects somehow `appcontroller.k8s/v1alpha1`
* [feisky](https://kubernetes.feisky.xyz/)
    * Chinese book on 1.6
* [security best practice](http://blog.kubernetes.io/2016/08/security-best-practices-kubernetes-deployment.html)
* [goat, security](https://madhuakula.com/kubernetes-goat/about.html)
    * Kubernetes Goat is designed to be intentionally vulnerable cluster environment to learn and practice Kubernetes security.
* [mantl.io](https://github.com/mantl)
    * integrated platform including a lot of stuff such as kubernetes, mesos
* [cloudnativelabs](https://cloudnativelabs.github.io/post/2017-05-1-kube-network-policies/)
    * enforcing kubernetes network with iptables
    * pseudo code for network policy operation, like adding to ipset
* [kube-gen](https://github.com/kylemcc/kube-gen)
    * generate file based on k8s event and metadata
* [kubewatch](https://github.com/skippbox/kubewatch)
    * watch k8s resource and send notification to Slack channel
* [posta training](http://blog.christianposta.com/kubernetes/3-day-docker-and-kubernetes-training/)
    * docker and kubernetes 4 day training by Christian Posta
* [draft](https://github.com/azure/draft)
    * a tool that scans source code and generate k8s objects
    * help geneartes Dockerfile, k8s YAML files, etc
* [brigade, microsoft, javascript, event](https://github.com/azure/brigade)
    * k8s event driven scripting using Javascript
    * builds container pipelines
    * k8s native
    * requires helm
* [life of a packet](https://www.youtube.com/watch?v=0Omvgd7Hg1I)
    * k8s networking video
    * [speakerdeck](https://speakerdeck.com/thockin/the-ins-and-outs-of-networking-in-google-container-engine)
        * by the same guy and Tim Hockin
        * not actually for kubernetes but still useful
* [which cni](https://chrislovecnm.com/kubernetes/cni/choosing-a-cni-provider/)
    * comments on various CNI
* [jolestar training](http://jolestar.com/kubernetes-complete-course/)
    * video traingin given by a guy from Qingcloud
* [JDOS](https://mp.weixin.qq.com/s/vyUi1V4pmYQr5_9T2Qqygg)
    * JD custmization of kuberntes
    * a lot of high level information but still readable
* [borg to kubernetes](https://www.youtube.com/watch?v=0W49z8hVn0k)
    * Youtube video
    * The key point of kubernetes and Borg is: resource scheduling optimisation
* [distro](https://docs.google.com/spreadsheets/d/1LxSqBzjOxfGx3cmtZ4EbB_BGCxT_wlxW_xgHVVa23es/edit#gid=0)
    * spreadsheet of k8s distributions
    * wise2c included
* [configuration management tools](https://docs.google.com/spreadsheets/d/1FCgqz1Ci7_VCz_wdh8vBitZ3giBtac_H8SBw4uxnrsE/edit#gid=0)
    * like helm
* [heptio kubernetes subscription](https://blog.heptio.com/introducing-heptio-kubernetes-subscription-5415052ef374)
    * integrated PaaS from heptio
* [gravitational](https://gravitational.com/blog/kubernetes-release-cycle/#)
    * kubernetes release cycle
    * LTS?
* [container runtimes](https://www.slideshare.net/PhilEstes/whose-job-is-it-anyway-kubernetes-cri-container-runtimes/?mkt_tok=eyJpIjoiTWpabFpHWTVaRGc1WmpGaSIsInQiOiJjOVJqaHBiYTVDU3g0RkJjVjdnK3FvbHAxWGtVWmQ5RXB2MnJsUHZtMDJtdW9Oc0lTcmd4NUZ5c21qd3l4UnRpZ1wvZzZVRURtYkwwQjExeG85RkVHN244Q1lKM1d3OFlsUkNKQlNBNFhwZFZKeWd1UFRDeHBMV2tNNjBGMkp6b1MifQ%3D%3D)
    * Whose Job is it anywa, CRI-O
* [codeship](https://resources.codeship.com/hubfs/Codeship_A-Roundup-of-Managed-Kubernetes-Platforms.pdf?t=1519673453469)
    * roundup of managed kubernetes platforms
    * PDF
    * GKE, openshift, Ubuntu, etc
* [50000](http://schd.ws/hosted_files/lc3china2017/d1/Scale%20Kubernetes%20to%20Support%2050000%20Services%20-%202017%20China.pdf)
    * scale kubernetes to 50000 services
* [rancher](http://schd.ws/hosted_files/lc3china2017/62/Fully%20Automated%20Kubernetes%20Deployment%20and%20Management.pdf)
    * PDF
    * talk by Jiang Peng
    * kubernetes upgrade
    * etc backup
    * health check
* [techbeacon](https://techbeacon.com/one-year-using-kubernetes-production-lessons-learned)
    * one year using kubernetes
    * run data service like MySQL and Mongo outside of kubernetes
    * cost: extra requirement of etcd, master nodes
    * logs sent directly from container themselves
    * published in 2016
* [ryan](https://medium.com/@ryandotclair/an-interrogation-of-metaparticle-and-abstraction-layers-44ba2fe07b62)
    * an interrogation of metaparticle
    * metaparticle: a leaky abstraction, breaks the law of sepration of concerns
* [newstack codeship](https://resources.codeship.com/hubfs/TheNewStack_Book101_KubernetesSolutionsDirectory.pdf)
    * kubernetes solution directory
* [coreos operator](https://coreos.com/blog/introducing-operators.html)
    * operator introduction
* [venturebeat](https://venturebeat.com/2018/05/05/everything-announced-at-kubecon-cloudnativecon-europe-2018/)
    * kubecon EU 2018 summary
* [objectif](https://www.objectif-libre.com/en/blog/2018/03/19/kubernetes-ipvs/)
    * ipvs and kubernetes
    * with a lot of pods on a host, ipvs performance much better than iptables: `O(1)`
    * [also see this pdf](https://schd.ws/hosted_files/cloudnativeeu2017/ce/Scale%20Kubernetes%20to%20Support%2050000%20Services.pdf)
* [containerd](https://kubernetes.io/blog/2018/05/24/kubernetes-containerd-integration-goes-ga/)
    * kubernetes containerd integration goes GA
    * kubernetes 1.10 + containerd 1.1
    * performance gain
    * docker engine will use containerd in the future
* [openai](https://blog.openai.com/scaling-kubernetes-to-2500-nodes/)
    * _scaling kubernetes to 2500 nodes_
    * etcd: move from networked storage to local SSD
    * etcd: increase hard storage limit
    * scheduler: schedule pods to a single node as much as it can
    * kubelet: `--serialize-image-pulls=false` to allow parallel image pull
    * docker: switch to overlay2
    * docker: move docker root to SSD
    * docker: max-concurrent-downloads option to 10
    * networking: `hostNetwork: true` and `dnsPolicy: ClusterFirstWithHostNet.`
    * networking: increased ARP cache size
* [eks](https://aws.amazon.com/blogs/aws/amazon-eks-now-generally-available/)
    * AWS EKS GA announcement
* [infoq](http://www.infoq.com/cn/presentations/different-ways-of-kubernetes-in-micro-service)
    * 宁辉
    * mentions SR-IOV
    * kubernetes + IaaS
* [gke-on-perm](https://cloud.google.com/gke-on-prem/)
    * private GKE
    * announced July 2018
* [kubeiql](https://kubeiql.io)
    * GraphQL interface for kubernetes
* [kubergui](https://github.com/BrandonPotter/kubergui)
    * GitHub - BrandonPotter/kubergui: Kubernetes GUI YAML generators for simple but typo-prone tasks
    * HTML yaml generator
* [freshtracks](https://blog.freshtracks.io/a-deep-dive-into-kubernetes-metrics-b190cc97f0f6)
    * a deep dive into kubernetes metrics (6 parts)
* [kubefwd](https://github.com/txn2/kubefwd)
    * GitHub - txn2/kubefwd: Bulk port forwarding Kubernetes services for local development.
    * developer tool to forward all remote service from a namespace
      transparently
    * access `/etc/hosts` to make sure local dev can access remote service with
      same name
* [itnext](https://itnext.io/benchmark-results-of-kubernetes-network-plugins-cni-over-10gbit-s-network-36475925a560)
    * CNI benchmark over 10G
    * calico, flannel, cilium, weave, canal
    * calico is good, cilium is confusingly bad
    * jumbo frame activated (MTU 9000) - MTU matters
* [rust, api](https://www.cloudatomiclab.com/rustyk8s/)
    * somebody is starting to write a k8s API with Rust
* [tinder, production, scale](https://medium.com/tinder-engineering/tinders-move-to-kubernetes-cda2a6372f44)
    * report from Tinder on moving to kubernetes
    * cluster size, flannel optimisation, dns problem, using envoy to fix HTTP Keepalive
    * 200 services, 1,000 nodes, 15,000 pods, and 48,000 running containers. 
* [google docs, cka](https://docs.google.com/presentation/d/13EQKZSQDounPC1I6EC4PmqaRmdCrpT3qswQJz9KRCyE/mobilepresent?slide=id.gd9c453428_0_16)
    * lengthy google spreadsheet with training material
* [alibaba, open source, kruise](https://github.com/openkruise/kruise)
    * Advanced StatefulSet, BroadcastJob, and SidecarSet open sourced by Alibaba
* [release, support](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/release/versioning.md)
    * Kubernetes Release Versioning
    * _Furthermore, we expect to "support" three minor releases at a time._
* [discuss](https://discuss.kubernetes.io)
    * discuss
* [tim hockin, kube-proxy, diagram](https://docs.google.com/drawings/d/1MtWL8qRTs6PlnJrW4dh8135_S9e2SaawT410bJuoBPk/edit)
    * kube-proxy NAT iptable flow
* [github, multipass, install](https://github.com/arashkaffamanesh/kubeadm-multipass)
    * Multi-Node Kubernetes 1.17 with kubeadm on local multipass cloud with Docker, Containerd or CRI-O and Rancher Server on top
* [golden, tools, google](https://docs.google.com/spreadsheets/d/1WPHt0gsb7adVzY3eviMK2W8LejV0I5m_Zpc8tMzl_2w/edit#gid=0)
    * The Golden Kubernetes Tooling and Helpers list
* [sheet, google, wise2c](https://docs.google.com/spreadsheets/d/1LxSqBzjOxfGx3cmtZ4EbB_BGCxT_wlxW_xgHVVa23es/edit#gid=0)
    * Google sheet with all distributions, including two from wise2c
* [kubecon 2019](https://github.com/ewohltman/kubecon2019)
    * Notes from KubeCon and EnvoyCon 2019.
* [CKA emulator](https://killer.sh/)
* [failure, bad](https://k8s.af/)
    * **K8s.af: When Kubernetes Goes Bad**
    * Kubernetes failure stories
* [medium, auth, client cert](https://medium.com/better-programming/k8s-tips-give-access-to-your-clusterwith-a-client-certificate-dfb3b71a76fe0
    * **Kubernetes Tips: Give Access To Your Cluster With A Client Certificate**
* [even, scheduling](https://kubernetes.io/blog/2020/05/introducing-podtopologyspread/)
    * **Introducing PodTopologySpread**
    * _distribute the Pods evenly across the topologies,_
* [aws](https://aws.amazon.com/about-aws/whats-new/2020/08/announcing-the-aws-controllers-for-kubernetes-preview/)
    * **Announcing the AWS Controllers for Kubernetes Preview**
* [gpu share](https://ml6.eu/a-guide-to-gpu-sharing-on-top-of-kubernetes/)
    * **A Guide to GPU Sharing on Top of Kubernetes**
* [banzai, gpu, GPU, 2020](https://banzaicloud.com/blog/gpu-accelerated-kubernetes/)
    * **GPU accelerated AI workloads on Kubernetes**
    * docker supports GPU, containerd doesn't yet
    * install [nvdia device plugin](https://github.com/NVIDIA/k8s-device-plugin)
    * test: run `nvidia-smi` in container
        1. NVIDIA drivers ~= 384.81
        1. nvidia-docker version > 2.0 (see how to install and it's prerequisites)
        1. docker configured with nvidia as the default runtime.
        1. Kubernetes version >= 1.10
* [caicloud, dao, tao](https://github.com/caicloud/kube-ladder)
    * **Learning Kubernetes, The Chinese Taoist Way**
