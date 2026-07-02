# invalid/invalid_embodied_gap

Mutation from valid/valid_embodied: rewrite `content/cam_latents.bin` with
frame 5 dropped (frames 0..4, 6..9 — simulating an agent deleting a frame
to conceal an event), then repair everything the kernel checks so the
continuity gap is the ONLY defect: `sources` hash for the stream updated,
Merkle root recomputed, manifest re-signed with the CI test key. The
manifest still lists `"profiles": ["embodied@1"]`, so a verifier that
implements the profile MUST run the continuity check and fail.

Expected: exit 1, E_BUFFER_DISCONTINUITY (profile error code, embodied@1).
A verifier that does not implement embodied@1 reports the profile in
profiles_unchecked and PASSES this shard — unchecked is not passed, and
this vector is only binding for verifiers claiming embodied@1 support.
