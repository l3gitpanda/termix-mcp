// Named tool groups, so a policy can say "@readonly" or "@exec" instead of
// enumerating 34 tool names. Enumeration is where hand-written and
// AI-generated policies go wrong: miss one name and the restriction has a hole
// nobody notices.
//
// These lists are asserted against the real registered tool catalog by the test
// suite, so a tool added later cannot silently fall outside every group -- and
// @readonly cannot silently drift away from "the tools that do not mutate".

export const TOOL_GROUPS = {
  '@hosts': ['list_hosts', 'host_status', 'host_metrics'],

  '@files.read': ['read_file', 'list_files', 'get_file_info'],
  '@files.write': [
    'write_file', 'create_file', 'create_directory',
    'delete_item', 'move_item', 'copy_item', 'change_permissions',
  ],
  '@files': [
    'read_file', 'list_files', 'get_file_info', 'find_file',
    'write_file', 'create_file', 'create_directory',
    'delete_item', 'move_item', 'copy_item', 'change_permissions',
  ],

  // Anything that can run arbitrary code on a host. find_file belongs here
  // because it is implemented over the command-execution path.
  '@exec': ['run_command', 'run_snippet', 'find_file'],

  '@docker': ['docker_containers', 'docker_container_info', 'docker_container_action'],
  '@system': ['list_services', 'service_action', 'list_processes', 'process_signal'],
  '@tunnels': ['list_tunnels', 'tunnel_action'],
  '@snippets': ['list_snippets', 'run_snippet'],
  '@observability': ['audit_logs', 'session_logs', 'recent_activity', 'alerts', 'alert_action'],
  '@meta': ['help', 'toggle_state', 'call_api'],

  // Authoring and checking the access policy itself. Read-only: neither tool
  // applies a policy or writes one to disk.
  '@policy': ['access_policy_schema', 'access_policy_check'],

  // Every tool that cannot change state. The safe grant for an observer.
  '@readonly': [
    'list_hosts', 'host_status', 'host_metrics',
    'read_file', 'list_files', 'get_file_info',
    'docker_containers', 'docker_container_info',
    'list_services', 'list_processes',
    'list_tunnels', 'list_snippets',
    'audit_logs', 'session_logs', 'recent_activity', 'alerts',
    'help', 'toggle_state',
    'access_policy_schema', 'access_policy_check',
    // call_api is NOT here, though its GET form does not mutate. `@readonly` is
    // what someone writes when they mean "this profile can look but not touch",
    // and including the generic API passthrough handed that profile the escape
    // hatch -- the policy checker even warned about it, which is the clearest
    // sign the group was named in a way that misled the person reaching for it.
    // Grant "call_api" explicitly when a profile genuinely needs it.
  ],

  // Tools that can escape a path restriction, because they run shell commands
  // or reach the API directly. Referenced by the policy linter.
  '@escape': ['run_command', 'run_snippet', 'find_file', 'call_api'],
};

export const GROUP_NAMES = Object.keys(TOOL_GROUPS);

// Expand any "@group" entries in a pattern list into the tool names they stand
// for. Unknown groups are an error rather than a silently-ignored no-op: a typo
// like "@readonyl" must not quietly widen or narrow a policy.
export function expandGroups(patterns, { where = 'tools' } = {}) {
  const out = [];
  for (const raw of patterns ?? []) {
    const pattern = String(raw);
    if (!pattern.startsWith('@')) {
      out.push(pattern);
      continue;
    }
    const members = TOOL_GROUPS[pattern];
    if (!members) {
      throw new Error(
        `unknown tool group "${pattern}" in ${where}; known groups are ${GROUP_NAMES.join(', ')}`,
      );
    }
    out.push(...members);
  }
  return [...new Set(out)];
}
