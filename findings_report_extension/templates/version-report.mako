# Overview for ${component_name}:${component_version}

# Artefact scan overview

ℹ️ ${len(total)} Artefacts have been identified

✅ ${len(scanned)} Artefacts have been scanned

❌ ${len(not_scanned)} Artefacts have not been scanned

🦠 ${len(with_findings)} Artefacts yielded ${finding_name} findings

% if len(with_findings) > 0:
<details>
  <summary><h1>🦠 ${finding_name.capitalize()} findings (${len(with_findings)})</h1></summary>

| Component | Artefact | Details |
|----|----|----|
% for component_artefact_id in with_findings:
| `${component_artefact_id.component_name}:${component_artefact_id.component_version}` | ${component_artefact_id.artefact_str} | ${'<br>'.join(issue_urls_by_component_artefact_id.get(component_artefact_id, ['no issue found']))} |
% endfor

</details>
% endif


% if len(not_scanned) > 0:
<details>
  <summary><h1>❌ Missing scans (${len(not_scanned)})</h1></summary>

| Component | Artefact |
|----|----|
% for component_artefact_id in not_scanned:
| `${component_artefact_id.component_name}:${component_artefact_id.component_version}` | ${component_artefact_id.artefact_str} |
% endfor
</details>
% endif

% if len(total) > 0:
<details>
  <summary><h1>ℹ️ Artefact Details (${len(total)})</h1></summary>

| Component | Resource |
|----|----|
% for component_artefact_id in total:
| `${component_artefact_id.component_name}:${component_artefact_id.component_version}` | ${component_artefact_id.artefact_str} |
% endfor
</details>
% endif
