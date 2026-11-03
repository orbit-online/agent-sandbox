package main

import (
	"encoding/json"
	"fmt"
)

// Folders: the broker's own mount capability, a host folder beneath one of permissions.folders mounted into the
// sandbox. Its id is the first design's, when folders were a plugin

const foldersID = "folders/folder"

// foldersCap is the folders capability with sources as its ceiling, none without sources
func foldersCap(sources []source) (*capability, error) {
	if len(sources) == 0 {
		return nil, nil
	}
	c := &capability{Name: foldersID, Type: "attach", Description: "a folder from the host", Sources: sources,
		Params: map[string]json.RawMessage{
			"path": json.RawMessage(`{"type": "string", "description": "the folder on the host: one list shows, or a folder beneath it"}`),
			"ro":   json.RawMessage(`{"type": "boolean", "description": "read-only, unless false; only what list marks rw may be read-write"}`),
		}}
	if err := c.check(); err != nil {
		return nil, fmt.Errorf("Folders: %w", err)
	}
	return c, nil
}

// folderOf is what a folder request asks for: its path, read-only unless ro is false
func folderOf(params json.RawMessage) (path string, ro bool) {
	var p struct {
		Path string `json:"path"`
		RO   *bool  `json:"ro"`
	}
	_ = json.Unmarshal(params, &p)
	return p.Path, p.RO == nil || *p.RO
}
