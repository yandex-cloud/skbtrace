package cli

import (
	"fmt"

	"github.com/mitchellh/go-wordwrap"
	"github.com/spf13/cobra"
	"github.com/yandex-cloud/skbtrace"
	"github.com/yandex-cloud/skbtrace/pkg/proto"
)

const (
	hintCommandRows   = "To see available rows, use 'fields' command."
	hintCommandFields = "To see available fields and their aliases, use 'fields' command."
	hintCommandProbes = "To see available probes, use 'probes' command." +
		" Note that kprobe: and kretprobe: prefixes support short k: and kr: forms."
	hintFormatField = "Field can be specified in the following formats:\n" +
		"  - '$obj->name' for struct field\n" +
		"  - 'alias' for field aliases or 'variable' for global variables\n"
	hintFormatFilter = "Filter can be specified in the format of: 'field op value'." +
		" Allowed operators: ==, !=, >, <, >=, <=."
	hintUnspecifiedProbe = "Probe name can be specified using -P (--probe) option." +
		" To see available options, use 'help' command."
	hintIPv6Address = "Specify flag '-6' to work with IPv6 packets."
)

type CommandBuilder func() (*skbtrace.Program, error)
type CommandRunFunc func(cmd *cobra.Command, args []string)

func NewRun(ctx *VisitorContext, builder CommandBuilder) CommandRunFunc {
	return func(cmd *cobra.Command, args []string) {
		prog, err := builder()
		if err != nil {
			handleBuilderError(ctx.Dependencies, err)
			ctx.Dependencies.Exit(2)
			return
		}

		err = skbtrace.Run(ctx.Dependencies.Output(), prog, ctx.RunnerOptions)
		if err != nil {
			fmt.Fprintln(ctx.Dependencies.ErrorOutput(), err)
		}
		ctx.Dependencies.Exit(1)
	}
}

func getBuilderErrorHint(skbErr skbtrace.Error) string {
	switch skbErr.Message() {
	case skbtrace.ErrMsgParseError:
		switch skbErr.Level() {
		case skbtrace.ErrLevelField:
			return hintFormatField
		case skbtrace.ErrLevelFilter:
			return hintFormatFilter + " " + hintFormatField
		}
	case skbtrace.ErrMsgNotFound:
		switch skbErr.Level() {
		case skbtrace.ErrLevelRow:
			return hintCommandRows
		case skbtrace.ErrLevelField:
			return hintCommandFields
		case skbtrace.ErrLevelProbe:
			return hintCommandProbes
		}
	case skbtrace.ErrMsgNotSpecified:
		switch skbErr.Level() {
		case skbtrace.ErrLevelProbe:
			return hintUnspecifiedProbe
		}
	}

	nextErr := skbErr.NextError()
	if addrErr, ok := nextErr.(*proto.InvalidIPv4AddressError); ok && addrErr.IsIPv6 {
		return hintIPv6Address
	}

	return ""
}

func handleBuilderError(deps Dependencies, err error) {
	fmt.Fprintln(deps.ErrorOutput(), "Error building skbtrace script.")

	var line string
	var hint string
	indent := "  - "
	for err != nil {
		if skbErr, ok := err.(skbtrace.Error); ok {
			line = fmt.Sprintf("Error in %s '%s': %s",
				skbErr.Level(), skbErr.Ident(), skbErr.Message())
			err = skbErr.NextError()

			errHint := getBuilderErrorHint(skbErr)
			if errHint != "" {
				hint = errHint
			}
		} else {
			line = err.Error()
			err = nil
		}

		fmt.Fprintln(deps.ErrorOutput(), indent, line)
		indent = "  " + indent
	}

	if hint != "" {
		fmt.Fprintln(deps.ErrorOutput(), "\n", wordwrap.WrapString(hint, 80))
	}
}
