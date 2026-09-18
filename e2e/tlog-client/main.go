package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const tileHeight = 8

type source struct{ base string }

func (s source) read(path string) ([]byte, error) {
	if strings.HasPrefix(s.base, "http://") || strings.HasPrefix(s.base, "https://") {
		resp, err := http.Get(strings.TrimRight(s.base, "/") + "/" + path)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: %s", path, resp.Status)
		}
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(filepath.Join(s.base, filepath.FromSlash(path)))
}

func c2spPath(t tlog.Tile) string {
	return strings.Replace(t.Path(), fmt.Sprintf("tile/%d/", tileHeight), "tile/", 1)
}

type tileReader struct {
	src  source
	size int64
}

func (r tileReader) Height() int { return tileHeight }

func (r tileReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, t := range tiles {
		data, err := r.src.read(c2spPath(t))
		if err != nil {
			return nil, err
		}
		out[i] = data
	}
	return out, nil
}

func (r tileReader) SaveTiles([]tlog.Tile, [][]byte) {}

func parseCheckpoint(text string) (origin string, tree tlog.Tree, err error) {
	lines := strings.Split(text, "\n")
	if len(lines) < 4 {
		return "", tree, fmt.Errorf("checkpoint has %d lines", len(lines))
	}
	n, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		return "", tree, err
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != tlog.HashSize {
		return "", tree, fmt.Errorf("malformed root hash line")
	}
	tree.N = n
	copy(tree.Hash[:], root)
	return lines[0], tree, nil
}

func leafData(src source, index, size int64) ([]byte, error) {
	bundle := index / 256
	t := tlog.Tile{H: tileHeight, L: 0, N: bundle, W: 256}
	if (bundle+1)*256 > size {
		t.W = int(size - bundle*256)
	}
	path := strings.Replace(c2spPath(t), "tile/0/", "tile/entries/", 1)
	data, err := src.read(path)
	if err != nil {
		return nil, err
	}
	for i := int64(0); ; i++ {
		if len(data) < 2 {
			return nil, fmt.Errorf("entry bundle ends before leaf %d", index)
		}
		n := int(binary.BigEndian.Uint16(data))
		if len(data) < 2+n {
			return nil, fmt.Errorf("entry bundle truncated")
		}
		if i == index%256 {
			return data[2 : 2+n], nil
		}
		data = data[2+n:]
	}
}

func run() error {
	base := flag.String("log", "", "Log directory or base URL")
	vkey := flag.String("key", "", "signed-note verifier key of the Log")

	flag.Parse()
	src := source{*base}

	verifier, err := note.NewVerifier(*vkey)
	if err != nil {
		return err
	}
	raw, err := src.read("checkpoint")
	if err != nil {
		return err
	}
	signed, err := note.Open(raw, note.VerifierList(verifier))
	if err != nil {
		return fmt.Errorf("checkpoint signature: %w", err)
	}
	origin, tree, err := parseCheckpoint(signed.Text)
	if err != nil {
		return err
	}
	if origin != verifier.Name() {
		return fmt.Errorf("origin %q is not the key name %q", origin, verifier.Name())
	}
	fmt.Printf("checkpoint verified: origin %s size %d root %x\n", origin, tree.N, tree.Hash[:])

	hashes := tlog.TileHashReader(tree, tileReader{src, tree.N})
	root, err := tlog.TreeHash(tree.N, hashes)
	if err != nil {
		return err
	}
	if root != tree.Hash {
		return fmt.Errorf("tiles reproduce root %x, checkpoint states %x", root[:], tree.Hash[:])
	}
	for index := int64(0); index < tree.N; index++ {
		data, err := leafData(src, index, tree.N)
		if err != nil {
			return err
		}
		leaf := tlog.RecordHash(data)
		stored, err := hashes.ReadHashes([]int64{tlog.StoredHashIndex(0, index)})
		if err != nil {
			return err
		}
		if !bytes.Equal(stored[0][:], leaf[:]) {
			return fmt.Errorf("entry bundle leaf %d does not hash to its tile entry", index)
		}
		proof, err := tlog.ProveRecord(tree.N, index, hashes)
		if err != nil {
			return err
		}
		if err := tlog.CheckRecord(proof, tree.N, tree.Hash, index, leaf); err != nil {
			return fmt.Errorf("inclusion of leaf %d: %w", index, err)
		}
	}
	fmt.Printf("inclusion verified: %d leaves\n", tree.N)

	for older := int64(1); older < tree.N; older++ {
		olderHash, err := tlog.TreeHash(older, hashes)
		if err != nil {
			return err
		}
		tp, err := tlog.ProveTree(tree.N, older, hashes)
		if err != nil {
			return err
		}
		if err := tlog.CheckTree(tp, tree.N, tree.Hash, older, olderHash); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}
