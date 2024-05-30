package cli

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

const rootShortHelp = "A thin wrapper around bpftrace which allows to trace socket buffer contents"
const rootHelp = rootShortHelp + `

Like any other bpftrace script, skbtrace is defined by probes to which it attaches actions. 
Two most common probes in skbtrace are 'recv' and 'xmit' which fire on receiving and transmitting 
the sk buffer respectively. Probes are specified using option -P, but some commands do so implicitly.
List of available probes can be printed with 'probes' command. 

skbtrace doesn't determine which protocols are encapsulated in the packet and instead requires 
hints to be specified, so only one type of the packet can be traced at a time. Hints include 
overlay encapsulation type (-e), IP version (-6) and transport protocol type (such as -p tcp).

Probe firings can be limited using filters in format '-F 'field == value'' with field being either 
an alias, fields without object such as global variable 'comm' or a full $obj->field notation. 
List of available fields is available in 'fields' command. There are also filter shortcuts such as '-i' 
which allows to specify network interface directly. 

skbtrace will track number of probe firings and number of firings which passed filtering either 
implicitly (in @hits array in dump-like commands) or by explicitly specifying 'evcount' subcommand 
for one of the 'timeit' command. 

Dump-like commands such as 'dump' and 'outliers' require specifying dumping rows using '-o' option.
List of available dump rows and field meanings can be printed with 'fields' command.

Time commands which map one event to another require lists of keys using in such mapping. Keys use same
syntax for fields as in filters. For example, '-k src,dst,sport,dport' will map packets having same five
tuple assuming that there is '-p tcp' or '-p udp' is supplied to determine the protocol.
`

var RootCommand = CommandProducer{
	Base: &cobra.Command{
		Use:   "skbtrace",
		Short: rootShortHelp,
		Long:  rootHelp,
	},
	Children: []*CommandProducer{
		CommonDumpTracerCommand,
		CommonAggregateCommand,
		CommonTimeItFromCommand,
		CommonDuplicateCommand,
		ProbesCommand,
		FieldsCommand,
		FeaturesCommand,
	},
}

func addHiddenCommands(rootCmd *cobra.Command) {
	completionCommand := &cobra.Command{
		Use:    "completion",
		Short:  "Generates bash completion scripts",
		Hidden: true,

		Run: func(cmd *cobra.Command, args []string) {
			rootCmd.GenBashCompletion(os.Stdout)
		},
	}

	docsCommand := &cobra.Command{
		Use:    "generate-md-docs DIR",
		Short:  "Generates markdown documentation",
		Args:   cobra.ExactArgs(1),
		Hidden: true,

		Run: func(cmd *cobra.Command, args []string) {
			doc.GenMarkdownTree(rootCmd, args[0])
		},
	}

	rootCmd.AddCommand(completionCommand, docsCommand)
}
