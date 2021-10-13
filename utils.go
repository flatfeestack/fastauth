package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

//https://yourbasic.org/golang/sort-map-keys-values/
func serialize(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b := new(bytes.Buffer)
	for _, k := range keys {
		fmt.Fprintf(b, "%s=\"%s\"\n", k, m[k])
	}
	return b.String()
}

func jsonToMeta(meta map[string]string) (string, error) {
	var metaJson string
	if meta == nil {
		metaJson = "{}"
	} else {
		metaByte, err := json.Marshal(meta)
		if err != nil {
			return "", fmt.Errorf("json convert failed: %v", err)
		}
		metaJson = string(metaByte)
	}
	return metaJson, nil
}

func mapToInterface(m1 map[string]string) map[string]interface{} {
	m2 := make(map[string]interface{}, len(m1))
	for k, v := range m1 {
		m2[k] = v
	}
	return m2
}

func removeUsedKeys1(meta map[string]string) map[string]string {
	retVal := map[string]string{}
	for k, v := range meta {
		found := false
		for _, j := range usedJsonKeys {
			if k == j {
				found = true
			}
		}
		if !found {
			retVal[k] = fmt.Sprintf("%v", v)
		}
	}
	return retVal
}

func removeUsedKeys2(meta map[string]interface{}) map[string]string {
	retVal := map[string]string{}
	for k, v := range meta {
		found := false
		for _, j := range usedJsonKeys {
			if k == j {
				found = true
			}
		}
		if !found {
			retVal[k] = fmt.Sprintf("%v", v)
		}
	}
	return retVal
}
