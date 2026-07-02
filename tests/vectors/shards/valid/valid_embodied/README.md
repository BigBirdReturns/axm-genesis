# valid/valid_embodied

Profile vector: the manifest lists `"profiles": ["embodied@1"]` and
`content/cam_latents.bin` is a gap-free AXLF stream (frames 0..9, 16-byte
payloads, record header `<4sBII` = AXLR | ver=1 | frame_id | length).

Built like valid/minimal but with `cam_latents.bin` in `content/` (hashed
into `sources` by the compiler), then `"profiles": ["embodied@1"]` was
added to the manifest and the manifest re-signed with the CI test key.

Expected: exit 0, status PASS, profiles_checked = ["embodied@1"]
(a verifier that does not implement embodied@1 must instead report it in
profiles_unchecked and still exit 0).
