// Copyright 2019 Hewlett Packard Enterprise Development LP
// Copyright 2017 The Kubernetes Authors.

package driver

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/kubernetes-csi/csi-lib-utils/protosanitizer"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	log "github.com/hpe-storage/common-host-libs/logger"
	"github.com/hpe-storage/common-host-libs/model"
	"github.com/hpe-storage/common-host-libs/util"
)

// ParseEndpoint parses the gRPC endpoint provided
func ParseEndpoint(ep string) (string, string, error) {
	if strings.HasPrefix(strings.ToLower(ep), "unix://") || strings.HasPrefix(strings.ToLower(ep), "tcp://") {
		s := strings.SplitN(ep, "://", 2)
		if s[1] != "" {
			return s[0], s[1], nil
		}
	}
	return "", "", fmt.Errorf("Invalid endpoint: %v", ep)
}

// NewControllerServiceCapability wraps the given type into a proper capability as expected by the spec
func NewControllerServiceCapability(capability csi.ControllerServiceCapability_RPC_Type) *csi.ControllerServiceCapability {
	return &csi.ControllerServiceCapability{
		Type: &csi.ControllerServiceCapability_Rpc{
			Rpc: &csi.ControllerServiceCapability_RPC{
				Type: capability,
			},
		},
	}
}

// NewNodeServiceCapability wraps the given type into a property capability as expected by the spec
func NewNodeServiceCapability(capability csi.NodeServiceCapability_RPC_Type) *csi.NodeServiceCapability {
	return &csi.NodeServiceCapability{
		Type: &csi.NodeServiceCapability_Rpc{
			Rpc: &csi.NodeServiceCapability_RPC{
				Type: capability,
			},
		},
	}
}

// NewPluginCapabilityVolumeExpansion wraps the given volume expansion into a plugin capability volume expansion required by the spec
func NewPluginCapabilityVolumeExpansion(capability csi.PluginCapability_VolumeExpansion_Type) *csi.PluginCapability_VolumeExpansion {
	return &csi.PluginCapability_VolumeExpansion{Type: capability}
}

// NewVolumeCapabilityAccessMode wraps the given access mode into a volume capability access mode required by the spec
func NewVolumeCapabilityAccessMode(mode csi.VolumeCapability_AccessMode_Mode) *csi.VolumeCapability_AccessMode {
	return &csi.VolumeCapability_AccessMode{Mode: mode}
}

func logGRPC(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	log.Infof("GRPC call: %s", info.FullMethod)
	log.Infof("GRPC request: %+v", protosanitizer.StripSecrets(req))
	resp, err := handler(ctx, req)
	if err != nil {
		log.Errorf("GRPC error: %v", err)
	} else {
		log.Infof("GRPC response: %+v", protosanitizer.StripSecrets(resp))
	}
	return resp, err
}

// Helper function to convert the epoch seconds to timestamp object
func convertSecsToTimestamp(seconds int64) *timestamp.Timestamp {
	return &timestamp.Timestamp{
		Seconds: seconds,
	}
}

// writeData persists data as json file at the provided location. Creates new directory if not already present.
func writeData(dir string, fileName string, data interface{}) error {
	dataFilePath := filepath.Join(dir, fileName)
	log.Tracef("saving data file [%s]", dataFilePath)

	// Encode from json object
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// Attempt create of staging dir, as CSI attacher can remove the directory
	// while operation is still pending(during retries)
	if err = os.MkdirAll(dir, 0750); err != nil {
		log.Errorf("Failed to create dir %s, %v", dir, err.Error())
		return err
	}

	// Write to file
	err = ioutil.WriteFile(dataFilePath, jsonData, 0600)
	if err != nil {
		log.Errorf("Failed to write to file [%s], %v", dataFilePath, err.Error())
		return err
	}
	log.Tracef("Data file [%s] saved successfully", dataFilePath)
	return nil
}

func removeDataFile(dirPath string, fileName string) error {
	log.Tracef(">>>>> removeDataFile, dir: %s, fileName: %s", dirPath, fileName)
	defer log.Trace("<<<<< removeDataFile")
	filePath := path.Join(dirPath, fileName)
	return util.FileDelete(filePath)
}

// isValidIP checks whether the provided string is a valid IP address.
// It returns true if the input is non-empty and can be parsed as an IP address,
// otherwise it returns false.
func isValidIP(ip string) bool {
	return ip != "" && net.ParseIP(ip) != nil
}

func getNetworkInterfaceIP(targetIP string, interfaceCIDRs []*string) (string, error) {
	log.Tracef(">>>>> GetNetworkInterfaceIP with targetIP: %s, interfaceCIDRs: %v", targetIP, interfaceCIDRs)
	defer log.Trace("<<<<< GetNetworkInterfaceIP")

	if targetIP == "" {
		return "", fmt.Errorf("target IP address cannot be empty")
	}

	if len(interfaceCIDRs) == 0 {
		return "", fmt.Errorf("interface CIDR list cannot be empty")
	}

	ip := net.ParseIP(targetIP)
	if ip == nil {
		return "", fmt.Errorf("invalid target IP address format: %s", targetIP)
	}

	var parseErrors []string
	for _, cidr := range interfaceCIDRs {
		if cidr == nil || *cidr == "" {
			continue // Skip empty CIDR entries
		}

		// Parse the CIDR to get both the interface IP and the network
		interfaceIP, ipnet, err := net.ParseCIDR(*cidr)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("invalid CIDR format '%s': %v", *cidr, err))
			continue
		}

		if ipnet.Contains(ip) {
			// Return the interface IP (the IP part from the CIDR) as IPv4
			ipAddr := interfaceIP.To4()
			if ipAddr != nil {
				log.Tracef("Found matching interface IP %s for target %s in CIDR %s", ipAddr.String(), targetIP, *cidr)
				return ipAddr.String(), nil
			}
		}
	}

	// If we had parse errors, include them in the final error message
	if len(parseErrors) > 0 {
		return "", fmt.Errorf("no matching network interface found for target IP %s. Parse errors encountered: %v", targetIP, parseErrors)
	}

	return "", fmt.Errorf("no matching network interface found for target IP %s in provided CIDR ranges: %v", targetIP, interfaceCIDRs)
}

// ValidateFileVolumeConfig validates required configuration keys for file volumes
// and returns a map of validated string values. Performs special validation for hostIP.
func ValidateFileVolumeConfig(volume *model.Volume, volumeID string, requiredKeys ...string) (map[string]string, error) {
	if volume.Config == nil {
		return nil, fmt.Errorf("config is nil for volume %s", volumeID)
	}

	configValues := make(map[string]string)

	for _, key := range requiredKeys {
		value, ok := volume.Config[key]
		if !ok || value == nil {
			return nil, fmt.Errorf("%s key not found or value is nil in config for volume %s", key, volumeID)
		}

		stringValue, ok := value.(string)
		if !ok || stringValue == "" {
			return nil, fmt.Errorf("failed to get %s for volume %s", key, volumeID)
		}

		// Special validation for hostIP key
		if key == fileHostIPKey && !isValidIP(stringValue) {
			return nil, fmt.Errorf("invalid hostIP value for volume %s: %s", volumeID, stringValue)
		}

		configValues[key] = stringValue
	}

	return configValues, nil
}

// IsSnapshotSupportedByCSP checks if the given CSP service supports snapshot operations.
// Returns true if snapshots are supported, false otherwise.
func IsSnapshotSupportedByCSP(serviceName string) bool {
	// If serviceName is empty, assume snapshot support (default behavior)
	if serviceName == "" {
		return true
	}
	// Check if CSP is in the unsupported list
	return !snapshotUnsupportedCSPs[serviceName]
}
