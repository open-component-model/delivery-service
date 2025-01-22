{{- define "secret" -}}
{{- range $secret_element_name, $value := $ }}
  {{ $secret_element_name }}: |{{ toYaml $value | nindent 4 }}
{{- end }}
{{- end -}}
