# Call-counter coverage matrix (rc3 Area H)

Contract-to-test map for the call-counter subsystem: every behavior the
design doc promises, and the committed test that pins it. Update this
file when a behavior changes; a row without a pin is a gap to fill with
a TDD pin plus a mutation check (break the code, watch the pin fail).

Conventions: `extract` = `tests/test_call_counters_extract.py`,
`structure` = `tests/test_call_counters_structure.py`, `contracts` =
`tests/test_call_counters_contracts.py`, `results` =
`tests/test_call_counters_results.py`, `durability` =
`tests/test_call_counters_durability.py`, `child` =
`tests/test_call_counters_child.py`, `unit` =
`tests/test_call_counters.py`, `module` =
`tests/test_call_counters_module.py`, `plugin` =
`tests/test_call_counters_plugin.py`, `preflight` =
`tests/test_call_counters_preflight.py`, `forensics` =
`tests/test_call_counters_forensics.py`, `provisioning` =
`tests/test_call_counters_provisioning.py`, `subprocess_safety` =
`tests/test_subprocess_safety_runtime_classification.py`.

## Buckets

| Behavior | Pin |
|---|---|
| Five buckets; default is `session_provisioning` | `unit::test_default_bucket_is_session_provisioning` |
| Regions nest, restore on exit (even on exception), isolate per thread | `unit::test_counted_bucket_pushes_and_pops_with_nesting`, `unit::test_counted_bucket_pops_on_exception` |
| Phase hooks attribute setup/test/teardown end to end | `plugin::test_phase_buckets_end_to_end` |
| Unknown explicit bucket raises | `unit::test_ingest_rejects_unknown_bucket` (+ `record_*` validation paths) |
| Five bucket keys emitted per module block | `contracts::TestForwardTask5Structure::test_emitted_blocks_uniform_five` |
| Provision bodies run under `session_provisioning` (6 + `_open_or_reinit`) | `provisioning::test_provision_body_runs_under_provisioning_region`, `provisioning::test_open_or_reinit_runs_under_provisioning_region` |
| Provision traffic moves buckets with conserved totals | `provisioning::test_provision_secret_key_create_path_moves_to_provisioning` |
| Nested `module_init` wins inside provisioning | `provisioning::test_open_or_reinit_retry_keeps_module_init_nested` |
| Gates outside provision bodies stay window-attributed | `provisioning::test_capability_gate_outside_provision_stays_window_attributed` |
| Orphan recovery folds under `test` (live bucket unknowable post-hoc) | `durability::TestProbeOrphanAdoption` family |
| `preflight` bucket for census/recovery children only | `preflight` census/recovery tests |

## Record types

| Behavior | Pin |
|---|---|
| Session/entry/partial/lost wire shapes (required/optional fields) | `contracts` schema suites, `structure` shape tests, `module` uuid/module-first tests |
| F2 self-describing block embedded when exported | `child::test_probe_sidecar_embeds_parent_identity` |
| F2 fields omitted when unset (legacy byte-identical) | `child::test_probe_sidecar_omits_identity_when_unset` |
| Malformed F2 attempt omits only attempt | `child::test_probe_sidecar_malformed_attempt_omits_attempt_only` |
| Malformed records skipped, never raise | `extract::test_extract_ignores_garbage_without_raising`, `extract::test_extract_skips_violating_session_record` |
| Malformed `run_id` skips the record whole | `extract::test_extract_malformed_run_id_skips_session_record`, `..._skips_test_entry` |

## Extractor rules

| Behavior | Pin |
|---|---|
| Session supersedes same-pid entries | `extract::test_extract_prefers_session_record_over_test_deltas` |
| Crashed/timed-out pid falls back to entry deltas | `extract::test_extract_crash_fallback_sums_deltas_and_marks_incomplete` |
| Retries count twice; torn-append uuid repeats fold first-wins | `extract::test_extract_retries_counted_twice` |
| Authoritative session supersedes same-producer partials, receipts union | `durability::test_authoritative_supersedes_partial_with_receipt_union` |
| Stale (same-run authoritative) losses reconcile away; pid-only never heals; other-run never heals | `durability::test_authoritative_session_heals_stale_loss`, `...::test_pid_only_loss_never_healed_by_session`, `...::test_loss_in_other_round_not_healed` |
| Counterless segments surface as `unattributed_segments`, no degenerate `""` block | `extract::test_extract_counterless_segment_is_unattributable_round`, `...::test_extract_first_setup_crash_marker_without_reports_is_incomplete`, `contracts::TestCharacterizationRc1::test_c2_and_c2b_emit_unattributed_segments` |
| Segments-only input yields a zero-call payload, never `None` | `extract::test_extract_first_setup_crash_marker_without_reports_is_incomplete` |
| `""` with data keeps its block beside segments; rounds are segment-blind | `extract::test_extract_implicit_round_with_data_keeps_block_beside_segments` |
| Unmarked segments carry null unit/attempt | `extract::test_extract_unmarked_segment_yields_null_unit_attempt` |
| Segments canonically sorted | `extract::test_extract_segments_sorted_by_scope` |
| Legacy run-less records fold into the implicit `""` round | `extract::test_extract_old_records_fold_into_implicit_round` |
| Per-round completeness independent; global ANDs rounds and segments-empty | `extract::test_extract_round_completeness_is_independent` |
| Same pid across rounds never fuses; reconciliation is run-scoped | `extract::test_extract_same_pid_across_rounds_never_fuses`, `...::test_extract_pid_reconciliation_is_run_scoped` |
| `probes_detail`: folded rows first, then net lost rows | `durability::test_lost_rows_follow_folded`, `durability::test_merge_carries_lost_processes_and_probes_detail` |
| Every session renders its row (clean-zero complete, not silent); loss rows carry `probes_lost` | `extract::test_extract_clean_zero_session_renders_complete_row`, `extract::test_extract_session_row_carries_pid_losses`, `durability::test_clean_zero_session_renders_complete_row`, `durability::test_zero_call_session_with_loss_gets_row` |
| Probe children persist sidecar snapshots on the record path (K cadence); failures warn once and continue; registered processes ignore leaked slots | `child::test_probe_child_flushes_sidecar_on_record_path`, `child::test_probe_child_sidecar_cadence_follows_k`, `child::test_probe_child_flush_failure_warns_once_and_continues`, `child::test_registered_process_ignores_probe_slot`, `child::test_sigkill_mid_probe_run_recovers_flushed_prefix` |
| Fork grandchildren isolate channels, reset to a delta baseline, write gcov; parent folds or notes | `subprocess_safety::test_fork_child_isolate_counters_drops_channels_keeps_seq`, `subprocess_safety::test_fork_child_writes_gcov_delta_not_parent_traffic`, `subprocess_safety::test_fork_parent_folds_gcov_without_note`, `subprocess_safety::test_fork_parent_notes_missing_gcov` |
| Zero-call session record is data | `extract::test_extract_zero_call_session_record_is_data` |
| Loss-anchored decoys own-group; C2b retained as segments | `structure::TestC2bAssociationInterplay` family |
| End-state conflicts surface `conflict`, never a silent pick | `durability::test_conflicting_terminals_become_conflict` |
| Mark rule (newer/older/missing seq) with conflict + loss-only arms | `durability::test_newer_mark_is_conflict_without_partial`, `...::test_older_mark_folds_all_valid_and_excludes_stale`, `...::test_missing_seq_folds_snapshot_only_plus_conflict` |

## Merge rules, gates, sort

| Behavior | Pin |
|---|---|
| Totals/modules/losses sum; `complete` ANDs; recomputed from shard extracts | `results::test_merge_shard_dirs_recomputes_call_counters_exactly` |
| Namespaced keys; colliding basenames disambiguate order-independently | `results::test_merge_duplicate_shard_basenames_disambiguate`, `...::test_merge_namespaces_same_run_id_across_shards` |
| Identical same-label snapshots fuse; different ones refuse loud | `results::test_merge_same_shard_identical_snapshot_still_fuses`, `...::test_merge_same_shard_inconsistent_snapshots_rejected_both_orders` |
| Untagged rows attribute to the round with rows (new + legacy shapes) | `results::test_merge_attributes_untagged_rows_to_round_with_rows`, `...::test_merge_legacy_degenerate_round_still_attributes_to_rows` |
| Conditional round/shard/module tags | `results::test_merge_rows_carry_round_and_shard_for_distinct_rounds`, `results::test_merge_single_shard_single_round_matches_extract_shape` |
| Merge-order independence (rows and segments) | `results::test_merge_shard_order_reversed_with_pid_collision_and_truncation`, `results::test_merge_shard_dirs_concatenates_segments_with_shard_tags` |
| Segments concatenate with conditional shard tags; single shard untagged | `results::test_merge_shard_dirs_concatenates_segments_with_shard_tags`, `...::test_merge_single_shard_segments_carry_no_shard_tag` |
| Malformed segment entries skip, never crash the merge | `results::test_merge_skips_malformed_segment_entries` (H gap pin, mutation-checked) |
| Detail triples union across statuses, never fuse | `results::test_merge_keeps_folded_and_lost_statuses_distinct` (H gap pin, mutation-checked) |
| Key omitted when no shard carries counters data | `results::test_merge_shard_dirs_omits_key_without_counters_data` |

## Rows and flags

| Behavior | Pin |
|---|---|
| One row per contributing (round, pid, module); module tag conditional | `extract::test_extract_by_process_assembly`, `contracts::TestForwardTask2ModuleFirst::test_module_tags_conditional` (stale marker; behavior pinned) |
| Isolation stamp precedence (session, fallback, unknown) | `contracts::TestForwardTask5Structure::test_entries_carry_stamped_isolation`, `...::test_fallback_rows_inherit_stamped_isolation` |
| `complete` at global, round, and row levels | `extract::test_extract_round_completeness_is_independent`, row-level asserts across `extract` |
| Lost rows name the accounting parent with `status: lost` | `durability::test_lost_rows_follow_folded` |

## Fence and collect paths

| Behavior | Pin |
|---|---|
| Registration precedes first call; torn registry reads as absent | `durability::test_torn_registry_reads_as_absent` |
| Torn registry with sidecar adopts sidecar identity; without, zero-loss absent | `durability::test_torn_registry_with_sidecar_adopts_sidecar_identity`, `...::test_torn_registry_without_sidecar_is_zero_loss_absent` |
| Fence terminates live writers; dead producers fence without signaling | `durability::test_fence_terminates_a_live_writer`, `...::test_dead_producer_fences_without_signaling` |
| Eager registration before probe spawn; sealed fails before spawn | `durability::TestEagerProbeRegistration` (incl. `test_run_probe_strips_ambient_probe_context_when_disengaged`, H gap pin, mutation-checked) |
| Runner exports F2 parent context | `durability::TestEagerProbeRegistration::test_run_probe_exports_parent_context` |
| Content-exact reunion heals prefix collisions | `durability::TestContentExactReunion::test_ambiguity_healed_by_content_match` |
| Legacy ambiguous orphans retain with one warning | `...::test_legacy_ambiguous_retained_and_warned` |
| Cross-run/cross-unit orphans and sidecars retain loudly | `...::test_cross_run_orphan_skipped`, `durability::TestStaleProducerSidecarFilter` |
| Mid-pass sidecars wait for the next pass (snapshot) | `...::test_mid_pass_orphan_excluded_from_this_pass` |
| Resume barrier adopts with prior claims | `durability::TestBarrierAdoptionE2E` |
| Barrier seals, collects, skips unresolved; releases for reruns | `durability::test_prepare_resume_seals_collects_and_skips_unresolved`, `...::test_prepare_resume_releases_seal_for_reruns` |
| Preflight child env scrubs counters + F2 keys | `preflight::TestDoctorExcluded::test_disengaged_child_env_scrubs_counters_keys` (F2 keys: H gap pin, mutation-checked) |

## Error modes

| Behavior | Pin |
|---|---|
| Sealed registration blocks provider entry, releases on unseal | `durability::test_sealed_registration_blocks_provider_entry_then_releases` |
| Seal landing mid-registration unlinks and blocks | `durability::test_seal_between_check_and_create_unlinks_and_blocks` |
| Entry rollback on failed flush (provider never ran) | Area A entry-rollback tests in `durability` |
| Return/direct/ingest retain + pending-marker + raise | `durability::test_record_return_retry_failure_retains_exit_and_marks_pending`, `...::test_failed_return_flush_retains_exit_and_sets_pending` |
| Pending marker blocks next entry; clears via flush/journal legs | `durability::test_pending_marker_blocks_next_entry_until_recovered`, `...::test_publish_clears_preexisting_marker_via_journal_leg` |
| Surviving marker forces counter-specific incomplete | `durability::test_surviving_marker_forces_session_incomplete` |
| Journal O_APPEND + remainder retry; close-after-complete is success | Area A journal tests in `durability` |
| Torn journal tails benign; garbage middles fold partial + conflict | `durability::test_torn_journal_tail_is_benign`, `...::test_garbage_journal_middle_yields_partial_plus_conflict` |
| K=1 cadence (window pin + immediate-flush behavior) | `durability::TestK1Cadence` (overhead measured ad-hoc per release; see the rc3 Area A overhead note) |

## Live proofs (suite-executed)

| Behavior | Pin |
|---|---|
| SIGKILL mid-first-test leaves the zero-counter segments shape | `forensics::test_sigkill_mid_first_test_leaves_zero_counter_shape` |
| Kill/retry accounting: exact, named, partial, or exact-but-truncated (XOR) | `forensics::test_sigkill_accounting_exact_or_named_or_partial`, `...::test_retry_dropped_accounting_exact_or_named_or_partial` |
| Recovery requeue drops first-attempt counters exactly once | `forensics::test_recovery_requeue_drops_first_attempt_counters` |

## Notes

- Stale forward markers (`TestForwardTask2ModuleFirst`) still execute
  their pins (XPASS runs them); un-staling them is out of rc3 scope.
  The Task-5 class was un-staled by Area C.
- Totals conservation across Area E is pinned at unit level (exact
  totals in `provisioning` outcome tests) and was additionally proven
  live against SoftHSM pre/post (295 = 295 with the split shifted;
  evidence in the Area E commit message). No committed live-provider
  test exists; the meta-suite uses fakes and fixtures.
- Overhead follows K: `TestK1Cadence::test_flush_window_is_one` locks
  the cadence; wall-clock overhead is measured ad-hoc per release with
  a stop-and-adjudicate rule (rc3 Area A note).
- Known residual (pre-existing, legacy-only): a legacy (pre-0.3.0,
  identity-less) orphan under an 8-char prefix collision retains
  loudly while its producer's anchors consume, so a staggered later
  collect could attribute it to the surviving collider. 0.3.0 never
  writes legacy orphans (the sidecar slot implies the F2 block, written
  atomically), so fresh dirs cannot hit this; fixing the legacy corner
  (anchor deferral or orphan quarantine) is follow-up material.
