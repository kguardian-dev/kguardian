package trivy

import (
	"encoding/json"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

// keptComponentProps are the CycloneDX properties NormaliseSBOM reads.
// Everything else Trivy writes (PkgID, LayerDiffID, SrcRelease, ...) is
// dropped before the object is cached.
var keptComponentProps = map[string]bool{
	propPkgType: true, propType: true, propClass: true, propSrcName: true,
	propSrcVersion: true, propLayerDigest: true, propFilePath: true,
}

// slimTransform is the informer transform: it decodes a report into the
// local mirror types (which already carry only the fields kguardian uses),
// prunes the SBOM's CycloneDX properties and metadata to what
// NormaliseSBOM reads, and stores that instead of the full object. Report
// descriptions, links, dependency graphs, hashes, suppliers and
// managedFields never reach the cache.
//
// An object that does not decode is stored unchanged, so the event handler
// sees and counts the decode error rather than the report vanishing.
func slimTransform(kind Kind) cache.TransformFunc {
	return func(obj interface{}) (interface{}, error) {
		u, ok := obj.(*unstructured.Unstructured)
		if !ok {
			return obj, nil // e.g. DeletedFinalStateUnknown
		}
		var report interface{}
		switch kind {
		case KindVulnerabilities:
			r, err := DecodeVulnerabilityReport(u.Object)
			if err != nil {
				return obj, nil
			}
			report = r.Report
		case KindSBOM:
			r, err := DecodeSbomReport(u.Object)
			if err != nil {
				return obj, nil
			}
			slimBOM(&r.Report.BOM)
			report = r.Report
		default:
			return obj, nil
		}
		reportMap, err := toMap(report)
		if err != nil {
			return obj, nil
		}
		slim := &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": u.GetAPIVersion(),
			"kind":       u.GetKind(),
			"report":     reportMap,
		}}
		slim.SetName(u.GetName())
		slim.SetNamespace(u.GetNamespace())
		slim.SetUID(u.GetUID())
		slim.SetResourceVersion(u.GetResourceVersion())
		labels := map[string]string{}
		for k, v := range u.GetLabels() {
			if strings.HasPrefix(k, "trivy-operator.") {
				labels[k] = v
			}
		}
		slim.SetLabels(labels)
		return slim, nil
	}
}

func slimBOM(b *bom) {
	for i := range b.Components {
		c := &b.Components[i]
		c.BOMRef = ""
		kept := c.Properties[:0]
		for _, p := range c.Properties {
			if keptComponentProps[p.Name] {
				kept = append(kept, p)
			}
		}
		c.Properties = kept
	}
	if b.Metadata != nil && b.Metadata.Component != nil {
		var kept []property
		for _, p := range b.Metadata.Component.Properties {
			if p.Name == propRepoDigest {
				kept = append(kept, p)
			}
		}
		b.Metadata = &bomMetadata{Component: &component{Properties: kept}}
	}
}

func toMap(v interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	err = json.Unmarshal(b, &m)
	return m, err
}
