package skb

import "github.com/yandex-cloud/skbtrace"

var taskFields = []*skbtrace.FieldGroup{
	{Row: "task", Object: "", Fields: []*skbtrace.Field{
		{Name: "comm", FmtSpec: "%s",
			Help: "First 16 bytes of command name as represented in kernel"},
		{Name: "pid", Help: "Process ID of current task"},
		{Name: "tid", Help: "Thread ID of current task"},
		{Name: "cpu", Help: "Processor number the probe has fired on"}}},
}

var taskVars = map[string]skbtrace.Expression{
	"comm": skbtrace.Expr("comm"),
	"pid":  skbtrace.Expr("pid"),
	"tid":  skbtrace.Expr("tid"),
	"cpu":  skbtrace.Expr("cpu"),
}

func RegisterTask(b *skbtrace.Builder) {
	b.AddFieldGroups(taskFields)
	b.AddGlobalVars(taskVars)
}
