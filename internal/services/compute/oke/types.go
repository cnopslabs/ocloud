package oke

import (
	"github.com/cnopslabs/ocloud/internal/services/util"
	"github.com/go-logr/logr"
	"github.com/oracle/oci-go-sdk/v65/containerengine"
)

type Service struct {
	containerEngineClient containerengine.ContainerEngineClient
	logger                logr.Logger
	compartmentID         string
}

type Cluster struct {
	Name            string
	ID              string
	CreatedAt       string
	Version         string
	State           containerengine.ClusterLifecycleStateEnum
	PrivateEndpoint string
	VcnID           string
	NodePools       []NodePool
	OKETags         util.ResourceTags
}

type NodePool struct {
	Name      string
	ID        string
	Version   string
	State     containerengine.NodePoolLifecycleStateEnum
	NodeShape string
	NodeCount int
	Image     string
	Ocpus     string
	MemoryGB  string
	NodeTags  util.ResourceTags
}

type JSONResponse struct {
	Clusters []Cluster `json:"clusters"`
}
