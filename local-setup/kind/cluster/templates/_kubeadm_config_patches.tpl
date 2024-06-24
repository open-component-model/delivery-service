{{- define "kubeadmConfigPatches" -}}
- |
  kind: InitConfiguration
  nodeRegistration:
    kubeletExtraArgs:
      node-labels: "ingress-ready=true"
- |
  apiVersion: kubelet.config.k8s.io/v1beta1
  kind: KubeletConfiguration
  serializeImagePulls: false # allow multiple image pulls at at time
  registryPullQPS: 10
  registryBurst: 20
{{- end -}}
