{{- define "extraMounts.delivery-db" -}}
- hostPath: /var/delivery-db
  containerPath: /var/delivery-db # has to match the spec.hostPath.path in the persistent volume
{{- end -}}
