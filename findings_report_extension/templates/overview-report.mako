# Overview for ${component_name}

# Artefact scan overview

Between ${start_date.isoformat()} and ${end_date.isoformat()},

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

# Detailed scan list

% for component_version in component_versions:
* [`${component_name}:${component_version}`](${f'./{reports_dirname}/{component_version}'})
% endfor
