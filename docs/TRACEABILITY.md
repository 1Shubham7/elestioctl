# Requirement traceability (R1 to R54)

One row per requirement in `spec/SPEC.md`. Test names are functions under
`tests/`; the file is given once per group. Every test carries its
requirement ID in its name or in a `// R<n>` comment on the line above.

Suite written black-box from `spec/SPEC.md` and `docs/API.md` only.
Status legend: **covered** means at least one test asserts the requirement;
**FAILING** means a test exists and the implementation currently disagrees
with the spec (details in the notes below the table); **GAP** means no test.

| Req | Summary | Tests | Status |
| --- | --- | --- | --- |
| R1 | Read `~/.elestio/credentials` (JSON `email`, `apiToken`), no own login flow | config: `r1_reads_credentials_from_dot_elestio_credentials`, `r1_config_dir_is_dot_elestio_under_home`, `r1_malformed_credentials_file_is_an_error_not_a_panic` | covered |
| R2 | Read `config.json` (`defaultProject`, `jwt`, `jwtExpiry`), missing file OK, fresh JWT (> 5 min) reused, no persistence | config: `r2_reads_default_project_jwt_and_expiry_from_config_json`, `r2_missing_config_json_is_not_an_error`, `r2_config_json_without_jwt_yields_no_cached_jwt`, `r2_cached_jwt_is_fresh_only_when_more_than_five_minutes_remain`; commands: `r2_fresh_cached_jwt_is_used_without_signing_in`, `r2_stale_cached_jwt_triggers_sign_in`, `r2_no_cached_jwt_triggers_sign_in`, `r2_cached_jwt_is_the_one_sent_in_later_calls`; cli: `r2_binary_uses_a_fresh_cached_jwt_without_signing_in`, `r2_binary_signs_in_when_the_cached_jwt_is_about_to_expire` | covered |
| R3 | `ELESTIO_EMAIL` / `ELESTIO_API_TOKEN` override the file; any env credential disables the cached JWT | config: `r3_environment_overrides_file_credentials`, `r3_environment_credentials_work_without_any_file`, `r3_environment_credentials_ignore_cached_jwt`, `r3_either_env_variable_alone_disables_cached_jwt`, `r3_env_constant_names_match_terraform_provider`; cli: `r3_binary_prefers_env_credentials_and_ignores_the_cache` | covered |
| R4 | Warn on stderr when credentials mode has any `0o077` bit, continue | config: `r4_group_or_other_readable_credentials_file_warns`, `r4_group_only_bit_also_warns`, `r4_owner_only_credentials_file_does_not_warn`; cli: `r4_world_readable_credentials_file_warns_on_stderr_and_continues` | covered |
| R5 | No credentials: exit 1, message names the file path and both env var names | config: `r5_no_credentials_error_names_path_and_both_env_vars`, `r5_empty_dot_elestio_directory_is_still_no_credentials`; cli: `r5_no_credentials_exits_1_naming_path_and_both_env_vars`, `r5_services_without_credentials_also_exits_1` | covered |
| R6 | Never print token or JWT; redacting `Debug`; JWT in body, never URL | config: `r6_secret_debug_is_redacted`, `r6_credentials_debug_redacts_token`, `r6_settings_debug_redacts_token_and_jwt`, `r6_cached_jwt_debug_redacts_jwt`, `r6_env_overrides_debug_redacts_token`, `r6_config_error_messages_never_contain_secrets`; client: `r6_jwt_travels_in_the_json_body_never_the_url`, `r6_api_client_debug_redacts_jwt`, `r6_client_errors_do_not_echo_the_jwt_or_token`, `r6_calls_needing_a_jwt_fail_before_sending_when_not_signed_in`; cli: `r6_binary_never_prints_token_or_jwt_even_with_debug` | covered |
| R7 | `--json`: single JSON document on stdout; errors plain text on stderr with empty stdout | cli: `r7_json_success_is_a_single_json_document`, `r7_json_error_leaves_stdout_empty_and_stderr_plain_text` (plus stdout-empty asserts in `r5_*`, `r11_argument_errors_exit_1_not_2`, `r20_*`, `r22_*`, `r27_*`, `r34_*`, `r35_*`, `r36_*`, `r37_*`) | covered |
| R8 | Human output aligned by padding; no ANSI codes | output: `r8_services_human_columns_are_aligned_by_padding`, `r8_table_helper_pads_with_spaces_and_has_no_ansi`; cli: `r8_no_ansi_escape_codes_anywhere` | covered |
| R9 | `--project` overrides `defaultProject` | commands: `r9_project_flag_overrides_default_project`; cli: `r9_project_flag_overrides_default_project` | covered |
| R10 | `--debug` prints the full cause chain one per line; otherwise a single line | cli: `r10_debug_prints_the_error_chain_one_cause_per_line` | covered |
| R11 | Exit codes 0 / 1 / 2; argument errors exit 1 | cli: `r11_argument_errors_exit_1_not_2`, `r11_success_exits_0`, `r11_network_error_exits_1` (plus `r51_*` for exit 2 and `r50_*` for exit 0) | covered |
| R12 | Errors name the operation that failed | cli: `r12_error_names_the_operation_that_failed`, `r12_auth_failure_names_the_sign_in_operation` | covered |
| R13 | Base URL via `ELESTIO_API_URL`, default `https://api.elest.io` | client: `r13_default_base_url_is_production`, `r13_base_url_is_configurable`; cli: `r13_api_url_env_var_points_the_binary_at_the_mock` | covered |
| R14 | Per-attempt timeout, default 30 s, `ELESTIO_TIMEOUT_SECS` | client: `r14_default_timeout_is_thirty_seconds_and_overridable_by_env_name`, `r14_per_attempt_timeout_is_enforced_and_timeouts_are_retried`; cli: `r14_timeout_secs_env_var_bounds_each_attempt` | covered |
| R15 | Retry 429/408/5xx/transport, 3 requests max, backoff `base * 2^(n-1)`, no retry on other 4xx or `KO` | client: `r15_retry_constants_match_spec`, `r15_retryable_status_set_is_exactly_408_429_and_5xx`, `r15_retries_5xx_three_times_in_total`, `r15_retries_429_then_succeeds`, `r15_retries_408_then_succeeds`, `r15_transport_error_is_retried_three_times`, `r15_backoff_is_base_times_two_to_the_n_minus_one`, `r15_other_4xx_is_not_retried`, `r15_ko_envelope_is_not_retried`; commands: `r15_drift_retries_a_flaky_details_call`; cli: `r15_binary_retries_5xx_three_times_then_fails`, `r15_binary_recovers_after_a_transient_5xx` | covered |
| R16 | Non-retried failure names the path and the HTTP status or the `KO` message | client: `r16_http_error_names_path_and_status`, `r16_ko_error_names_path_and_api_message`, `r16_ko_without_message_still_names_path` | covered |
| R17 | Malformed JSON: parse error naming the JSON path, no panic | client: `r17_non_json_body_is_a_parse_error_not_a_panic`, `r17_wrong_field_type_names_the_json_path`, `r17_wrong_container_type_names_the_json_path`, `r17_firewall_rule_missing_required_field_names_path` | **FAILING** (see note 1) |
| R18 | `auth test` calls `checkAPIToken`, ignoring any cached JWT | client: `r18_sign_in_posts_email_and_token_to_check_api_token`; commands: `r18_auth_test_always_signs_in_even_with_fresh_cache`; cli: `r18_auth_test_ignores_a_fresh_cached_jwt` | covered |
| R19 | Success prints the email; `--json` has `authenticated` and `email` | commands: `r19_auth_report_carries_the_authenticated_email`; output: `r19_auth_human_prints_the_email`, `r19_auth_json_has_authenticated_and_email`; cli: `r19_auth_test_human_prints_the_email`, `r19_auth_test_json_has_authenticated_and_email` | covered |
| R20 | Auth failure exits 1; rejection distinct from "no credentials" | client: `r20_sign_in_rejected_when_status_is_not_ok`, `r20_sign_in_rejected_when_ok_but_no_jwt`; commands: `r20_auth_test_rejection_is_a_distinct_error`; cli: `r20_rejected_credentials_exit_1_and_are_not_confused_with_missing_ones`, `r20_ok_without_jwt_is_also_a_rejection` | covered |
| R21 | List services for the resolved project | client: `r21_list_services_sends_spec_body_and_normalises_vmid`; commands: `r21_list_services_returns_the_project_services`; cli: `r21_services_lists_the_project` | covered |
| R22 | No project: exit 1 naming `--project` and `elestio config --set-default-project <id>` | commands: `r22_no_project_error_names_flag_and_official_command`; drift_config: `r22_resolve_without_any_project_names_the_service_and_the_fix`; cli: `r22_no_project_exits_1_naming_flag_and_official_command`, `r22_drift_without_any_project_exits_1` | covered |
| R23 | Human columns: id, name, template, version, provider, datacenter, server type, status | output: `r23_services_human_column_order`, `r23_services_human_snapshot`; cli: `r23_services_human_columns_in_spec_order` | covered |
| R24 | Empty list reported explicitly | output: `r24_empty_service_list_is_reported_explicitly`; cli: `r24_empty_service_list_is_reported_explicitly` | covered |
| R25 | `--json` array with exactly the nine keys; empty array when none | output: `r25_services_json_has_exactly_the_nine_keys`, `r25_services_json_empty_is_empty_array`; cli: `r25_services_json_is_an_array_with_exactly_nine_keys`, `r25_services_json_empty_is_an_empty_array` | covered |
| R26 | `service <vmID>` fetches and displays one service | client: `r26_get_service_sends_vmid_and_project_id`; commands: `r26_get_service_returns_the_service`; output: `r26_service_json_has_the_same_nine_keys`, `r26_service_human_shows_every_mapped_field`; cli: `r26_service_shows_details_for_one_id` | covered |
| R27 | Empty `serviceInfos`: not-found error naming vmID and project, exit 1, distinct from network failure | client: `r27_empty_service_infos_is_none_not_an_error`; commands: `r27_not_found_error_names_vmid_and_project`, `r27_network_failure_is_not_reported_as_not_found`; cli: `r27_unknown_vmid_exits_1_with_not_found_naming_id_and_project` | covered |
| R28 | No credential endpoints; `managedDBCLI` and `adminUser` omitted; no `--show-secrets` | commands: `r28_secret_bearing_fields_are_dropped_from_the_model`; output: `r28_secret_fields_never_appear_in_output`; cli: `r28_service_output_omits_managed_db_cli_and_admin_user`, `r28_show_secrets_flag_does_not_exist`; client: `r53_allowlist_holds_exactly_the_four_spec_triples` (refuses `getAppCredentials`, `getServiceEnv`) | covered |
| R29 | Firewall rules fetched after details; `isFirewallActivated = 0` reported as disabled | client: `r29_firewall_rules_use_the_get_firewall_rules_action`, `r29_firewall_rules_accept_the_nested_data_rules_shape`, `r29_firewall_rule_targets_accept_a_bare_string`; commands: `r29_enabled_firewall_fetches_details_then_rules`, `r29_disabled_firewall_is_reported_as_disabled`, `r29_firewall_get_on_unknown_service_is_not_found`, `r29_disabled_firewall_means_declared_rules_are_absent`; output: `r29_disabled_firewall_says_disabled_not_zero_rules`; cli: `r29_firewall_get_fetches_details_then_rules`, `r29_disabled_firewall_says_disabled` | covered |
| R30 | Human output per rule: type, port, protocol, targets joined by `, ` | output: `r30_firewall_human_shows_type_port_protocol_and_joined_targets`, `r30_firewall_human_snapshot`; cli: `r29_firewall_get_fetches_details_then_rules` (`// R30` block) | covered |
| R31 | INPUT rule with `0.0.0.0/0` or `::/0` marked; `--json` `open_to_internet` boolean | output: `r31_open_to_internet_predicate`, `r31_open_rules_are_marked_in_human_output`, `r31_firewall_json_carries_open_to_internet_per_rule`; cli: `r31_firewall_json_marks_open_to_internet`, `r29_firewall_get_fetches_details_then_rules` (`// R31` block) | covered |
| R32 | TOML shape, `project` fallbacks, `firewall_mode` default `subset` | drift_config: `r32_parses_the_spec_example`, `r32_id_may_be_an_integer`, `r32_id_may_be_a_string`, `r32_firewall_mode_defaults_to_subset`, `r32_firewall_mode_exact_is_accepted`, `r32_unknown_firewall_mode_is_rejected`, `r32_top_level_project_is_optional`, `r32_services_keep_file_order`, `r32_resolve_project_precedence_per_service_then_top_level_then_fallback`, `r32_resolve_carries_every_declared_field`, `r32_empty_file_is_a_valid_config_with_no_services`; cli: `r32_drift_project_falls_back_to_flag_then_default_project` | covered |
| R33 | Every field but `id` optional; absent `firewall` unchecked; `firewall = []` asserts none | drift_config: `r33_every_field_except_id_is_optional`, `r33_explicit_empty_firewall_is_some_empty_not_none`, `r33_partial_declaration_leaves_other_fields_none`; diff: `r33_firewall_none_skips_the_firewall_check_entirely`; commands: `r33_absent_firewall_key_never_fetches_rules`, `r33_empty_firewall_list_asserts_no_rules`; cli: `r33_undeclared_fields_and_firewall_are_not_checked`, `r33_explicit_empty_firewall_in_exact_mode_flags_every_actual_rule` | covered |
| R34 | Malformed TOML: parse error naming the line, exit 1 | drift_config: `r34_malformed_toml_names_the_line`, `r34_unterminated_string_names_the_line`, `r34_load_reports_a_missing_file_as_an_io_error`, `r34_load_reads_a_file_from_disk`; cli: `r34_malformed_toml_exits_1_naming_the_line`, `r34_missing_config_file_exits_1_naming_the_path` | covered |
| R35 | `[[service]]` without `id`: validation error naming the zero-based index | drift_config: `r35_service_without_id_names_its_zero_based_index`, `r35_first_service_without_id_is_index_zero`; cli: `r35_service_without_id_exits_1_naming_the_index` | covered |
| R36 | Duplicate ids: validation error naming the id | drift_config: `r36_duplicate_ids_name_the_id`, `r36_distinct_ids_are_fine`; cli: `r36_duplicate_ids_exit_1_naming_the_id` | covered |
| R37 | Fetch each declared service; any fetch error exits 1 with no drift output | commands: `r37_drift_fetches_each_declared_service_in_its_project`, `r37_fetch_error_aborts_the_whole_drift_command`, `r37_ko_envelope_aborts_drift`; cli: `r37_fetch_error_exits_1_with_no_drift_output` | covered |
| R38 | `Difference` carries service id, field path, declared, actual | diff: `r38_mismatch_carries_id_field_declared_and_actual`, `r38_declared_field_absent_in_actual_is_a_mismatch_with_none`, `r38_only_declared_fields_are_compared` | covered |
| R39 | Service not returned: `Missing`, not an error; no cross-project search | diff: `r39_missing_service_is_a_missing_difference`, `r39_id_absent_from_actual_map_is_missing`; commands: `r39_not_found_service_is_missing_not_an_error`; cli: `r39_missing_service_is_reported_not_an_error` | covered |
| R40 | Rules compared as a set; type/protocol case-insensitive; port/targets exact; duplicates collapse | diff: `r40_rule_order_does_not_matter`, `r40_type_and_protocol_compare_case_insensitively`, `r40_port_compares_exactly`, `r40_targets_compare_exactly_and_as_a_set`, `r40_duplicate_rules_collapse_to_one`, `r40_duplicate_targets_collapse_to_one`, `r40_rule_from_api_model_is_canonical`; drift_config: `r40_declared_rules_are_canonicalised_on_parse` | covered |
| R41 | `Absent` for declared-not-actual; `Unexpected` only in `exact` mode | diff: `r41_declared_rule_not_in_actual_is_absent`, `r41_subset_mode_never_reports_unexpected`, `r41_exact_mode_reports_unexpected`, `r41_exact_mode_with_empty_declaration_reports_every_actual_rule`; commands: `r41_drift_subset_ignores_extra_actual_rules_and_reports_absent` | covered |
| R42 | Deterministic order: declared order; fields `name, server_type, provider, datacenter, version`; `Absent` before `Unexpected`, each sorted | diff: `r42_scalar_field_order_is_fixed`, `r42_fields_before_firewall_absent_before_unexpected_each_sorted`, `r42_rule_ord_is_type_port_protocol_targets`, `r42_services_reported_in_declared_order`; diff_props: `r47_determinism_same_inputs_same_differences_and_bytes` (`// R42` block); cli: `r51_drift_detected_exits_2_with_r48_lines` | covered |
| R43 | Reflexivity: `diff(declare_all(A), A)` is empty (proptest) | diff_props: `r43_reflexivity_declare_all_yields_no_differences`; diff: `r43_declare_all_asserts_every_field_in_exact_mode` | covered |
| R44 | Emptiness: no services, or id-only declarations, yield nothing (proptest) | diff_props: `r44_no_declared_services_yields_no_differences`, `r44_id_only_declarations_yield_no_differences` | covered |
| R45 | Detection: a changed scalar or rule is reported on that field (proptest) | diff_props: `r45_changed_scalar_is_detected_on_that_field`, `r45_changed_firewall_rule_is_detected_on_firewall_field` | covered |
| R46 | Set semantics: any permutation of rules and targets is equal in exact mode (proptest) | diff_props: `r46_set_semantics_any_permutation_is_equal_in_exact_mode`, `r46_case_variants_and_duplicates_are_still_equal` | covered |
| R47 | Determinism: equal difference lists and byte-identical output (proptest) | diff_props: `r47_determinism_same_inputs_same_differences_and_bytes`; report: `r47_rendering_is_deterministic` | covered |
| R48 | Human drift lines in the four exact formats | report: `r48_mismatch_line_format`, `r48_missing_line_format`, `r48_firewall_absent_line_format`, `r48_firewall_unexpected_line_format`, `r48_render_line_has_no_trailing_newline`, `r48_render_human_is_one_line_per_difference_in_given_order`, `r48_human_report_snapshot`; diff: `r48_rule_render_format`; cli: `r51_drift_detected_exits_2_with_r48_lines`, `r39_missing_service_is_reported_not_an_error`, `r33_explicit_empty_firewall_in_exact_mode_flags_every_actual_rule` | covered |
| R49 | `--json`: `{ drift_detected, differences[] }` with `kind`, `service_id`, `field`, `declared`, `actual` | report: `r49_json_shape`, `r49_json_no_drift`, `r49_json_snapshot`; cli: `r49_drift_json_shape`, `r50_no_drift_json_has_drift_detected_false` | covered (see note 3) |
| R50 | No drift: `No drift detected.` and exit 0; zero services warns and exits 0 | report: `r50_no_drift_exact_string`; commands: `r50_no_differences_means_no_drift`, `r50_zero_declared_services_is_not_an_error`; cli: `r50_no_drift_prints_exact_line_and_exits_0`, `r50_no_drift_json_has_drift_detected_false`, `r50_zero_services_is_not_an_error_prints_no_drift_and_warns` | covered |
| R51 | Drift found: exit 2 | commands: `r51_drift_detected_when_any_difference_exists`; cli: `r51_drift_detected_exits_2_with_r48_lines`, `r49_drift_json_shape`, `r39_missing_service_is_reported_not_an_error` | covered |
| R52 | `#![forbid(unsafe_code)]` at the crate root | safety: `r52_crate_root_forbids_unsafe_code`, `r52_manifest_also_forbids_unsafe_code` | covered |
| R53 | Closed allowlist of (method, path, action); anything else refused before sending; mock sees zero requests | client: `r53_allowlist_holds_exactly_the_four_spec_triples`, `r53_endpoint_enum_matches_spec_paths`, `r53_call_off_the_allowlist_sends_zero_requests`, `r53_do_action_with_other_action_sends_zero_requests`, `r53_wrong_method_on_allowed_path_sends_zero_requests`, `r53_allowed_call_through_request_is_sent_once` | covered |
| R54 | Writes nothing anywhere, including the JWT | config: `r54_loading_config_creates_nothing_in_home`; cli: `r54_binary_writes_nothing_under_an_empty_home`, `r54_no_credentials_path_writes_nothing_either`, `r2_binary_signs_in_when_the_cached_jwt_is_about_to_expire` (`// R54` block: `config.json` byte-identical after a fresh sign-in) | covered |

## Gaps

None. Every requirement R1 to R54 has at least one test that names it.

## Notes on failing tests and observations

1. **R17, FAILING:** `tests/client.rs::r17_non_json_body_is_a_parse_error_not_a_panic`.
   Spec: malformed JSON in a response MUST produce a parse error. Observed:
   a `200` whose body is `<html>gateway</html>` surfaces as
   `ClientError::Transport { attempts: 3, source: reqwest Decode error }`
   and the request is sent three times. The body decode failure is being
   classified as a transport error and retried; R15 lists 429, 408, 5xx and
   transport errors as the only retry triggers, and a 200 with an unparsable
   body is none of them. Expected: `ClientError::Parse`, one request.
2. **R17, observation (tests pass):** for a wrong field type the parse error
   reads `... at [1].vmID: ...` and for a missing field `... at [0]: missing
   field \`port\``. The path is relative to the array that was being
   deserialised (`servers`, `rules`) rather than to the response root, so the
   container name is not part of the path. The tests accept the
   array-relative form because it still locates the failing element and
   field; a full path (`servers[1].vmID`) would be clearer.
3. **R49, observation (tests pass):** the `missing` element in `--json`
   output carries a sixth key, `project`, in addition to the five the spec
   lists. The spec does not forbid extra keys, so the tests assert the five
   required keys are present rather than exact key sets. `docs/API.md` says
   "every element carries the same five keys", which is not what the code
   does for `missing`.
4. **R48, observation:** when a declared scalar has no actual value (the API
   omitted the field) the mismatch line renders `actual=(absent)`. The spec
   gives no rendering for a `None` actual; `(absent)` is accepted.
5. **API shape, not a spec matter:** `ApiClient::get_service`,
   `commands::get_service` and `commands::firewall_get` take `(project,
   vm_id)` in that order. `docs/API.md` truncates these signatures, and the
   first draft of the tests assumed `(vm_id, project)`; the tests were
   corrected, but the generated API document should show full signatures.
6. **Test harness note:** a dropped `wiremock::MockServer` returns to a pool
   and keeps listening, so it cannot be used to obtain a dead port. The
   transport-error tests bind and release a `TcpListener` instead.
