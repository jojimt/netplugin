/***
Copyright 2017 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/docker/libnetwork/drivers/remote/api"

	log "github.com/Sirupsen/logrus"
)

func main() {
	var dockerNWId string
	var endpointID string
	var homingHost string

	// parse rest of the args that require creating state
	flagSet := flag.NewFlagSet("reclaimep", flag.ExitOnError)

	flagSet.StringVar(&homingHost,
		"homingHost",
		"",
		"homingHost as seen in inspect")

	flagSet.StringVar(&dockerNWId,
		"dockerNwId",
		"",
		"Docker network uuid as seen from docker inspect network")

	flagSet.StringVar(&endpointID,
		"endpointID",
		"",
		"endpointID as seen in netctl inspect")

	if err := flagSet.Parse(os.Args[1:]); err != nil {
		log.Fatalf("Failed to parse command. Error: %s", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("Could not retrieve hostname: %v", err)
	}

	if hostname != homingHost {
		log.Fatalf("This host is %s. Please run from %s", hostname, homingHost)
	}

	c := newClient()
	epInfo := api.DeleteEndpointRequest{
		NetworkID:  dockerNWId,
		EndpointID: endpointID,
	}

	DelEP(c, &epInfo)
}

func unixDial(proto, addr string) (conn net.Conn, err error) {
	sock := "/run/docker/plugins/netplugin.sock"
	return net.Dial("unix", sock)
}

func newClient() *http.Client {
	transport := &http.Transport{Dial: unixDial}
	client := &http.Client{Transport: transport}

	return client
}

// DelEP deletes an ep
func DelEP(c *http.Client, epInfo interface{}) error {

	buf, err := json.Marshal(epInfo)
	if err != nil {
		return err
	}

	body := bytes.NewBuffer(buf)
	url := "http://localhost/NetworkDriver.DeleteEndpoint"
	r, err := c.Post(url, "application/json", body)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	switch {
	case r.StatusCode == int(404):
		return fmt.Errorf("page not found")
	case r.StatusCode == int(403):
		return fmt.Errorf("access denied")
	case r.StatusCode != int(200):
		log.Errorf("GET Status '%s' status code %d \n", r.Status, r.StatusCode)
		return fmt.Errorf("%s", r.Status)
	}

	return nil
}
