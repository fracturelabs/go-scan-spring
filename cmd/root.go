package cmd

import (
	"fmt"
	"os"

	"github.com/fracturelabs/go-scan-spring/lib"
	"github.com/spf13/cobra"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

)

var (
	options = lib.NewOptions()
)

var rootCmd = &cobra.Command{
	Use:   "go-scan-spring",
	Short: "Spring vulnerability scanner",
	Long: `Spring vulnerability scanner`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "2006-01-02T15:04:05-0700"})
		if options.Debug {
			log.Logger = log.Logger.Level(zerolog.DebugLevel)
			log.Logger = log.With().Caller().Logger()
		} else {
			log.Logger = log.Logger.Level(zerolog.InfoLevel)
		}

		options.Logger = &log.Logger
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&options.Debug, "debug", false, "enable debug logging")
}


