// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package translator // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/datadogreceiver/internal/translator"

import (
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/tinylib/msgp/msgp"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/DataDog/datadog-agent/pkg/obfuscate"
	pb "github.com/DataDog/datadog-agent/pkg/proto/pbgo/trace"
	"github.com/DataDog/datadog-agent/pkg/trace/stats"
	"github.com/DataDog/datadog-agent/pkg/trace/traceutil"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/datadogreceiver/internal/translator/header"
)

const (
	maxResourceLen = 5000

	// keyStatsPayload is the key for the stats payload in the attributes map.
	// This is used as Metric name and Attribute key.
	keyStatsPayload = "dd.internal.stats.payload"

	textNonParsable = "Non-parsable SQL query"
)

func TranslateStats(req *http.Request) (pmetric.Metrics, error) {
	req.Header.Set("Accept", "application/msgpack")
	clientStats := &pb.ClientStatsPayload{}
	if err := msgp.Decode(req.Body, clientStats); err != nil {
		return pmetric.NewMetrics(), err
	}

	clientStats = processStats(clientStats, req.Header.Get(header.Lang), req.Header.Get(header.TracerVersion))

	sp := &pb.StatsPayload{
		Stats:          []*pb.ClientStatsPayload{clientStats},
		ClientComputed: true,
	}

	bytes, err := proto.Marshal(sp)
	if err != nil {
		return pmetric.NewMetrics(), err
	}

	mmx := pmetric.NewMetrics()
	rmx := mmx.ResourceMetrics().AppendEmpty()
	smx := rmx.ScopeMetrics().AppendEmpty()
	mslice := smx.Metrics()
	mx := mslice.AppendEmpty()
	mx.SetName(keyStatsPayload)
	sum := mx.SetEmptySum()
	sum.SetIsMonotonic(false)
	dp := sum.DataPoints().AppendEmpty()
	byteSlice := dp.Attributes().PutEmptyBytes(keyStatsPayload)
	byteSlice.Append(bytes...)
	return mmx, nil
}

func processStats(in *pb.ClientStatsPayload, lang, tracerVersion string) *pb.ClientStatsPayload {
	in.Env = traceutil.NormalizeTag(in.Env)
	if in.TracerVersion == "" {
		in.TracerVersion = tracerVersion
	}
	if in.Lang == "" {
		in.Lang = lang
	}

	for i, group := range in.Stats {
		n := 0
		for _, b := range group.Stats {
			normalizeStatsGroup(b, lang)
			obfuscateStatsGroup(b)
			group.Stats[n] = b
			n++
		}
		in.Stats[i].Stats = group.Stats[:n]
		mergeDuplicates(in.Stats[i])
	}

	return in
}

func normalizeStatsGroup(b *pb.ClientGroupedStats, lang string) {
	b.Name, _ = traceutil.NormalizeName(b.Name)
	b.Service, _ = traceutil.NormalizeService(b.Service, lang)
	if b.Resource == "" {
		b.Resource = b.Name
	}
	b.Resource, _ = truncateResource(b.Resource)
}

func obfuscateStatsGroup(b *pb.ClientGroupedStats) {
	o := obfuscate.NewObfuscator(obfuscate.Config{})
	switch b.Type {
	case "sql", "cassandra":
		oq, err := o.ObfuscateSQLString(b.Resource)
		if err != nil {
			b.Resource = textNonParsable
		} else {
			b.Resource = oq.Query
		}
	case "redis":
		b.Resource = o.QuantizeRedisString(b.Resource)
	}
}

// truncateResource truncates a span's resource to the maximum allowed length.
// It returns true if the input was below the max size.
func truncateResource(r string) (string, bool) {
	return traceutil.TruncateUTF8(r, maxResourceLen), len(r) <= maxResourceLen
}

func mergeDuplicates(s *pb.ClientStatsBucket) {
	indexes := make(map[stats.Aggregation]int, len(s.Stats))
	for i, g := range s.Stats {
		a := stats.NewAggregationFromGroup(g)
		if j, ok := indexes[a]; ok {
			s.Stats[j].Hits += g.Hits
			s.Stats[j].Errors += g.Errors
			s.Stats[j].Duration += g.Duration
			s.Stats[i].Hits = 0
			s.Stats[i].Errors = 0
			s.Stats[i].Duration = 0
		} else {
			indexes[a] = i
		}
	}
}
