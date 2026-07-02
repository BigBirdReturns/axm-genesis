package axm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// checkEmbodied1 implements the embodied@1 profile
// (spec/profiles/embodied@1.md section 6): the hot stream
// content/cam_latents.bin must be a gap-free, append-only AXLF/AXLR
// sequence. Absent file = vacuous pass. The check stops at the first
// violation; the traversal advances by each header's declared payload_len.
func checkEmbodied1(v *verifier) []ErrorItem {
	const rel = "content/cam_latents.bin"
	disc := func(format string, args ...any) []ErrorItem {
		vv := &verifier{}
		vv.addf("E_BUFFER_DISCONTINUITY", "embodied@1 "+rel+": "+format, args...)
		return vv.errs
	}

	f, err := os.Open(v.shardFile(rel))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // vacuous pass
		}
		return disc("unreadable: %v", err)
	}
	defer f.Close()

	fileMagic := make([]byte, 4)
	if _, err := io.ReadFull(f, fileMagic); err != nil {
		return disc("shorter than the 4-byte AXLF file header")
	}
	if !bytes.Equal(fileMagic, []byte("AXLF")) {
		return disc("bad file magic %q, want AXLF", fileMagic)
	}

	expected := uint32(0)
	hdr := make([]byte, 13)
	for {
		n, err := io.ReadFull(f, hdr)
		if err == io.EOF && n == 0 {
			return nil // clean EOF: the check passes
		}
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				return disc("truncated record header at frame %d", expected)
			}
			return disc("read error at frame %d: %v", expected, err)
		}
		if !bytes.Equal(hdr[0:4], []byte("AXLR")) {
			return disc("bad record magic %q at frame %d, want AXLR", hdr[0:4], expected)
		}
		if hdr[4] != 1 {
			return disc("bad record version %d at frame %d, want 1", hdr[4], expected)
		}
		frameID := binary.LittleEndian.Uint32(hdr[5:9])
		payloadLen := binary.LittleEndian.Uint32(hdr[9:13])
		if frameID != expected {
			return disc("frame gap: got frame_id %d, want %d", frameID, expected)
		}
		if skipped, err := io.CopyN(io.Discard, f, int64(payloadLen)); err != nil || skipped != int64(payloadLen) {
			return disc("truncated payload at frame %d (%d of %d bytes)", frameID, skipped, payloadLen)
		}
		expected++
	}
}
