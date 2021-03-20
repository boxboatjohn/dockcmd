// Copyright © 2019 BoxBoat engineering@boxboat.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	elasticsearch6 "github.com/elastic/go-elasticsearch/v6"
	elasticsearch7 "github.com/elastic/go-elasticsearch/v7"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"strconv"
	"time"
)

var (
	esDryRun        bool
	esPrettyPrint   bool
	esURL           string
	esVersion       string
	esAPIKey        string
	esUsername      string
	esPassword      string
	esRetentionDays int
	es6Client       *elasticsearch6.Client
	es7Client       *elasticsearch7.Client
)

type sixClient struct{
	Client *elasticsearch6.Client
}

type sevenClient struct {
	Client *elasticsearch7.Client
}

type Client interface {
	Find([]string) map[string]interface{}
	Delete([]string)
}

func (c *sixClient) Delete(indices []string) {
	c.Client.Indices.Delete(indices)
}

func (c *sevenClient) Delete(indices []string) {
	c.Client.Indices.Delete(indices)
}

func (c *sixClient) Find(search []string) map[string]interface{} {
	var indices map[string]interface{}
	response, err := c.Client.Indices.Get(search)
	HandleError(err)
	if response.IsError() {
		HandleError(
			fmt.Errorf(
				"Error: %s",
				response.String()))
	}
	json.NewDecoder(response.Body).Decode(&indices)

	return indices
}

func (c *sevenClient) Find(search []string) map[string]interface{} {
	var indices map[string]interface{}
	response, err := c.Client.Indices.Get(search)
	HandleError(err)
	if response.IsError() {
		HandleError(
			fmt.Errorf(
				"Error: %s",
				response.String()))
	}
	json.NewDecoder(response.Body).Decode(&indices)

	return indices
}

func deleteIndex(client Client, delete []string) {
	client.Delete(delete)
}

func findIndices(client Client, search []string) map[string]interface{} {
	return client.Find(search)
}

func NewES6Client() (Client, error){
	var client sixClient

	cfg := elasticsearch6.Config{
		Addresses: []string{
			esURL,
		},
		Username: esUsername,
		Password: esPassword,
		APIKey:   esAPIKey,
	}
	es6Client, err := elasticsearch6.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	client.Client = es6Client
	return &client, err
}

func NewES7Client() (Client, error) {
	var client sevenClient

	cfg := elasticsearch7.Config{
		Addresses: []string{
			esURL,
		},
		Username: esUsername,
		Password: esPassword,
		APIKey:   esAPIKey,
	}
	es7Client, err := elasticsearch7.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	client.Client = es7Client
	return &client, err
}


func getESClient() Client {
	var client Client
	var err error
	if esVersion == "v6" {
		client, err = NewES6Client()
	}
	if esVersion == "v7" {
		client, err = NewES7Client()
	}
	HandleError(err)

	Logger.Debugf("Using %s client", esVersion)
	Logger.Debugf("Username:[%s]", esUsername)
	Logger.Debugf("Password:[%s]", esPassword)
	Logger.Debugf("ApiKey:[%s]", esAPIKey)

	return client
}

var esDeleteIndicesCmd = &cobra.Command{
	Use:   "delete-indices",
	Short: "Delete matching indices from Elasticsearch",
	Long:  `Provide an index name to delete from Elasticsearch`,
	Run: func(cmd *cobra.Command, args []string) {
		Logger.Debug("delete-indices called")

		var search []string
		if len(args) == 1 {
			search = args
		} else {
			HandleError(errors.New("Provide delete string"))
		}
		Logger.Debugf("Deleting [%s] from elasticsearch", search)

		client := getESClient()

		indices := findIndices(client, search)

		for k, v := range indices {
			settings := v.(map[string]interface{})["settings"].(map[string]interface{})
			index := settings["index"].(map[string]interface{})
			creationDateMs, err := strconv.ParseInt(index["creation_date"].(string), 10, 64)
			HandleError(err)

			Logger.Debugf("key[%s] creationDate[%s]\n", k, index["creation_date"])

			age := time.Now().Sub(time.Unix(0, creationDateMs*int64(time.Millisecond)))
			Logger.Debugf("Age[%s]\n", age)
			if age.Seconds() > float64(esRetentionDays*24.0*60.0*60.0) {
				if esDryRun == false {
					fmt.Printf("Deleting index [%s]\n", k)
					client.Delete([]string{k})
				} else {
					fmt.Printf("[%s] would be deleted\n", k)
				}
			}
		}

	},
}

var esGetIndicesCmd = &cobra.Command{
	Use:   "get-indices",
	Short: "Retrieve list of matching indices from Elasticsearch",
	Long:  `Provide an index name to query Elasticsearch`,
	Run: func(cmd *cobra.Command, args []string) {
		Logger.Debug("get-indices called")

		var search []string
		if len(args) == 1 {
			search = args
		} else {
			HandleError(errors.New("Provide search string"))
		}
		Logger.Debugf("Searching elasticsearch for [%s]", search)

		client := getESClient()

		indices := client.Find(search)
		var out []byte
		var err error
		if esPrettyPrint {
			out, err = json.MarshalIndent(indices, "", "  ")
		} else {
			out, err = json.Marshal(indices)
		}
		HandleError(err)
		fmt.Println(string(out))
	},
}

// esCmdPersistentPreRunE checks required persistent tokens for esCmd
func esCmdPersistentPreRunE(cmd *cobra.Command, args []string) error {
	if err := rootCmdPersistentPreRunE(cmd, args); err != nil {
		return err
	}
	Logger.Debugln("esCmdPersistentPreRunE")
	Logger.Debugf("Using ES URL: {%s}", esURL)
	esURL = viper.GetString("url")
	esUsername = viper.GetString("username")
	esPassword = viper.GetString("password")
	esAPIKey = viper.GetString("api-key")

	if esURL == "" {
		return errors.New("${ES_URL} must be set or passed in via --url")
	}
	return nil
}

// esCmd represents the es command
var esCmd = &cobra.Command{
	Use:               "es",
	Short:             "Elasticsearch Commands",
	Long:              `Commands designed to facilitate interactions with Elasticsearch`,
	PersistentPreRunE: esCmdPersistentPreRunE,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(esCmd)
	esCmd.AddCommand(esGetIndicesCmd)
	esCmd.AddCommand(esDeleteIndicesCmd)

	esCmd.PersistentFlags().StringVarP(
		&esURL,
		"url",
		"",
		"",
		"Elasticsearch URL can alternatively be set using ${ES_URL}")
	viper.BindEnv("url", "ES_URL")

	esCmd.PersistentFlags().StringVarP(
		&esVersion,
		"api-version",
		"",
		"",
		"Elasticsearch major version, currently supports v6 and v7 e.g. --api-version v6")

	esCmd.PersistentFlags().StringVarP(
		&esUsername,
		"username",
		"",
		"",
		"Elasticsearch username for Basic Auth can alternatively be set using ${ES_USERNAME}")
	viper.BindEnv("username", "ES_USERNAME")

	esCmd.PersistentFlags().StringVarP(
		&esPassword,
		"password",
		"",
		"",
		"Elasticsearch password for Basic Auth can alternatively be set using ${ES_PASSWORD}")
	viper.BindEnv("password", "ES_PASSWORD")

	esCmd.PersistentFlags().StringVarP(
		&esAPIKey,
		"api-key",
		"",
		"",
		"Elasticsearch Base64 encoded authorization api token - will override Basic Auth can alternatively be set using ${ES_API_KEY}")
	viper.BindEnv("api-key", "ES_API_KEY")

	viper.BindPFlags(esCmd.PersistentFlags())

	esGetIndicesCmd.Flags().BoolVarP(
		&esPrettyPrint,
		"pretty-print",
		"",
		false,
		"Pretty print json output")

	esDeleteIndicesCmd.Flags().IntVarP(
		&esRetentionDays,
		"retention-days",
		"",
		0,
		"Days to retain indexes matching delete pattern")
	esDeleteIndicesCmd.Flags().BoolVarP(
		&esDryRun,
		"dry-run",
		"",
		false,
		"Enable dry run to see what indices would be deleted")

}
