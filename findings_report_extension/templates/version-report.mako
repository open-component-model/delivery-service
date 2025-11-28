# Overview for ${component_name}:${component_version}

# Resource scan overview

ℹ️ ${len(resource_nodes)} Resources have been identified

✅ ${len(scanned)} Resources have been scanned

❌ ${len(not_scanned)} Resources have not been scanned

🦠 ${len(with_findings)} Resources yielded malware findings

% if len(with_findings) > 0:
<details>
  <summary><h1>🦠 Malware findings (${len(with_findings)})</h1></summary>

| Component | Resource | Details |
|----|----|----|
% for resource_node in with_findings:
| ${resource_node.component.name}:`${resource_node.component.version}` | [${resource_node.resource.name}:`${resource_node.resource.version}`](${resource_node.resource.access.imageReference}) | ${issue_url_for_resource_node.get(resource_node.resource.identity(peers=resource_node.component.resources), 'no issue found')} |
% endfor

</details>
% endif


% if len(not_scanned) > 0:
<details>
  <summary><h1>❌ Missing scans (${len(not_scanned)})</h1></summary>

| Landscape version | Component | Resource |
|----|----|----|
% for resource_node in not_scanned:
| ${resource_node.path[0].component.version} | ${resource_node.component.name}:`${resource_node.component.version}` | [${resource_node.resource.name}:`${resource_node.resource.version}`](${resource_node.resource.access.imageReference}) |
% endfor
</details>
% endif

% if len(resource_nodes) > 0:
<details>
  <summary><h1>ℹ️ Resource Details (${len(resource_nodes)})</h1></summary>

| Component | Resource |
|----|----|
% for resource_node in resource_nodes:
| ${resource_node.component.name}:`${resource_node.component.version}` | [${resource_node.resource.name}:`${resource_node.resource.version}`](${resource_node.resource.access.imageReference}) |
% endfor
</details>
% endif
