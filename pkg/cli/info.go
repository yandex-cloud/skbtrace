package cli

import (
	"fmt"
	"github.com/yandex-cloud/skbtrace"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var ProbesCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:   "probes",
		Short: "Shows list of known probes",
	},

	InfoVisitor: func(ctx *VisitorContext, cmd *cobra.Command) {
		cmd.Run = func(cmd *cobra.Command, args []string) {
			probes := ctx.Builder.Probes()

			tw := tablewriter.NewWriter(ctx.Dependencies.Output())
			tw.SetHeader([]string{"PROBE", "ARGS", "HELP"})
			tw.SetColWidth(80)
			tw.SetColMinWidth(2, 60)
			for _, probe := range probes {
				row := make([]string, 3)

				if len(probe.Aliases) == 0 {
					row[0] = probe.Name
				} else {
					row[0] = fmt.Sprintf("%s (%s)", probe.Aliases[0],
						strings.Join(append(probe.Aliases[1:], probe.Name), ", "))
				}

				var argNames []string
				for arg, obj := range probe.Args {
					argNames = append(argNames, fmt.Sprintf("%s(%s)", arg, obj))
				}
				row[1] = strings.Join(argNames, ", ")

				row[2] = probe.Help
				tw.Append(row)
			}
			tw.Render()
		}
	},
}

var FieldsCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:   "fields [ROW]",
		Short: "Shows list of known fields",
	},

	InfoVisitor: func(ctx *VisitorContext, cmd *cobra.Command) {
		cmd.Run = func(cmd *cobra.Command, args []string) {
			fieldGroups := ctx.Builder.FieldGroups()

			tw := tablewriter.NewWriter(ctx.Dependencies.Output())
			tw.SetHeader([]string{"ROW", "OBJECT", "FIELD", "KEY", "HELP"})
			tw.SetAutoMergeCells(true)
			tw.SetColWidth(80)
			tw.SetColMinWidth(4, 60)
			tw.SetRowLine(true)
			for _, fg := range fieldGroups {
				if fg.BaseFieldGroup != "" {
					help := fmt.Sprintf("Same fields as in %s (%s)", fg.Row, fg.Object)
					if fg.FieldAliasPrefix != "" {
						help = fmt.Sprintf("%s. Field aliases use prefix %s-*",
							help, fg.FieldAliasPrefix)
					}

					row := []string{
						fg.Row, fg.Object, "", "", help,
					}
					tw.Append(row)
					continue
				}

				for _, field := range fg.Fields {
					fieldName := field.Name
					if field.Alias != "" {
						fieldName = fmt.Sprintf("%s (%s)", field.Alias, fieldName)
					}

					row := []string{
						fg.Row, fg.Object, fieldName, field.FmtKey, field.Help,
					}
					tw.Append(row)
				}
			}
			tw.Render()
		}
	},
}

var FeaturesCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:   "features",
		Short: "Shows list of supported features and their state",
	},

	InfoVisitor: func(ctx *VisitorContext, cmd *cobra.Command) {
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			tw := tablewriter.NewWriter(ctx.Dependencies.Output())
			tw.SetHeader([]string{"COMPONENT", "MINVER", "FEATURE", "STATE", "HELP"})

			componentMap := ctx.Dependencies.FeatureComponents()
			for compName, spec := range componentMap {
				features := skbtrace.GetKnownFeatures(spec.Component)
				mask := ctx.FeatureFlagMasks[spec.Component]

				for _, feature := range features {
					tw.Append([]string{
						compName,
						feature.MinVersion.String(),
						feature.Name,
						fmt.Sprint(mask.Supports(feature)),
						feature.Help,
					})
				}
			}

			tw.Render()
			return nil
		}
	},
}
