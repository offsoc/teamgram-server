package examples

import (
	"time"

	"github.com/teamgram/teamgram-server/pkg/crypto/hsm"
)

// GetThalesLunaConfig returns a configuration for Thales Luna HSM
func GetThalesLunaConfig() *hsm.HSMConfig {
	return &hsm.HSMConfig{
		Vendor:           hsm.VendorThalesLuna,
		LibraryPath:      "/usr/lib/libCryptoki2_64.so", // Thales Luna PKCS#11 library
		SlotID:           0,
		PIN:              "your-hsm-pin",
		Label:            "TeamGram-Luna-HSM",
		ConnectTimeout:   30 * time.Second,
		OperationTimeout: 5 * time.Second,
		MaxRetries:       3,
		MaxSessions:      20,
		SessionPoolSize:  10,
		ThalesConfig: &hsm.ThalesConfig{
			HAGroup:        "TeamGram-HA-Group",
			ClientCertPath: "/etc/hsm/client.pem",
			ClientKeyPath:  "/etc/hsm/client.key",
			ServerCertPath: "/etc/hsm/server.pem",
			HAOnly:         true,
			RecoveryMode:   false,
		},
		Options: map[string]string{
			"enable_ha":       "true",
			"failover_mode":   "automatic",
			"load_balancing":  "round_robin",
		},
	}
}

// GetUtimacoConfig returns a configuration for Utimaco CryptoServer
func GetUtimacoConfig() *hsm.HSMConfig {
	return &hsm.HSMConfig{
		Vendor:           hsm.VendorUtimaco,
		LibraryPath:      "/opt/utimaco/lib/libcs_pkcs11_R2.so", // Utimaco PKCS#11 library
		SlotID:           1,
		PIN:              "your-hsm-pin",
		Label:            "TeamGram-Utimaco-HSM",
		ConnectTimeout:   30 * time.Second,
		OperationTimeout: 5 * time.Second,
		MaxRetries:       3,
		MaxSessions:      15,
		SessionPoolSize:  8,
		UtimacoConfig: &hsm.UtimacoConfig{
			Device:     "3001@192.168.1.100",
			Timeout:    30,
			AuthMethod: "password",
			KeyStore:   "TEAMGRAM_KEYSTORE",
			AdminAuth:  false,
		},
		Options: map[string]string{
			"cluster_mode":    "enabled",
			"backup_device":   "3001@192.168.1.101",
			"sync_keys":       "true",
		},
	}
}

// GetAWSCloudHSMConfig returns a configuration for AWS CloudHSM
func GetAWSCloudHSMConfig() *hsm.HSMConfig {
	return &hsm.HSMConfig{
		Vendor:           hsm.VendorAWSCloudHSM,
		LibraryPath:      "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so", // AWS CloudHSM PKCS#11 library
		SlotID:           0,
		PIN:              "your-crypto-user-pin",
		Label:            "TeamGram-CloudHSM",
		ConnectTimeout:   30 * time.Second,
		OperationTimeout: 5 * time.Second,
		MaxRetries:       3,
		MaxSessions:      25,
		SessionPoolSize:  12,
		CloudHSMConfig: &hsm.CloudHSMConfig{
			ClusterID:       "cluster-abcd1234efgh5678",
			Region:          "us-east-1",
			AccessKeyID:     "AKIA...", // AWS Access Key
			SecretAccessKey: "...",     // AWS Secret Key
			SessionToken:    "",        // Optional session token
			ENI:             "eni-0123456789abcdef0",
			CustomerCA:      "/opt/cloudhsm/etc/customerCA.crt",
		},
		Options: map[string]string{
			"cluster_backup":  "enabled",
			"multi_az":        "true",
			"auto_scaling":    "enabled",
		},
	}
}

// GetSoftHSMConfig returns a configuration for SoftHSM (testing)
func GetSoftHSMConfig() *hsm.HSMConfig {
	return &hsm.HSMConfig{
		Vendor:           hsm.VendorSoftHSM,
		LibraryPath:      "/usr/lib/softhsm/libsofthsm2.so", // SoftHSM PKCS#11 library
		SlotID:           0,
		PIN:              "1234",
		Label:            "TeamGram-SoftHSM-Test",
		ConnectTimeout:   10 * time.Second,
		OperationTimeout: 2 * time.Second,
		MaxRetries:       2,
		MaxSessions:      10,
		SessionPoolSize:  5,
		Options: map[string]string{
			"token_dir":       "/var/lib/softhsm/tokens/",
			"object_store":    "file",
			"log_level":       "INFO",
		},
	}
}

// GetSimulatorConfig returns a configuration for HSM simulator (development)
func GetSimulatorConfig() *hsm.HSMConfig {
	return &hsm.HSMConfig{
		Vendor:           hsm.VendorSimulator,
		SlotID:           0,
		PIN:              "simulator-pin",
		Label:            "TeamGram-HSM-Simulator",
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 1 * time.Second,
		MaxRetries:       1,
		MaxSessions:      5,
		SessionPoolSize:  3,
		Options: map[string]string{
			"simulation_mode": "fips_140_3_level_4",
			"random_source":   "crypto_rand",
			"key_storage":     "memory",
		},
	}
}

// GetHSMPoolConfig returns a configuration for HSM pool with failover
func GetHSMPoolConfig() *hsm.PoolConfig {
	return &hsm.PoolConfig{
		MaxRetries:          3,
		RetryDelay:          100 * time.Millisecond,
		HealthCheckInterval: 30 * time.Second,
		LoadBalanceStrategy: hsm.RoundRobin,
		FailoverEnabled:     true,
		MaxConcurrentOps:    100,
	}
}

// GetProductionHSMConfigs returns production-ready HSM configurations
func GetProductionHSMConfigs() []*hsm.HSMConfig {
	return []*hsm.HSMConfig{
		// Primary Thales Luna HSM
		{
			Vendor:           hsm.VendorThalesLuna,
			LibraryPath:      "/usr/lib/libCryptoki2_64.so",
			SlotID:           0,
			PIN:              "primary-hsm-pin",
			Label:            "TeamGram-Primary-HSM",
			ConnectTimeout:   30 * time.Second,
			OperationTimeout: 5 * time.Second,
			MaxRetries:       3,
			MaxSessions:      20,
			SessionPoolSize:  10,
			ThalesConfig: &hsm.ThalesConfig{
				HAGroup:        "TeamGram-Primary-HA",
				ClientCertPath: "/etc/hsm/primary/client.pem",
				ClientKeyPath:  "/etc/hsm/primary/client.key",
				ServerCertPath: "/etc/hsm/primary/server.pem",
				HAOnly:         true,
				RecoveryMode:   false,
			},
		},
		// Secondary Thales Luna HSM (for failover)
		{
			Vendor:           hsm.VendorThalesLuna,
			LibraryPath:      "/usr/lib/libCryptoki2_64.so",
			SlotID:           1,
			PIN:              "secondary-hsm-pin",
			Label:            "TeamGram-Secondary-HSM",
			ConnectTimeout:   30 * time.Second,
			OperationTimeout: 5 * time.Second,
			MaxRetries:       3,
			MaxSessions:      20,
			SessionPoolSize:  10,
			ThalesConfig: &hsm.ThalesConfig{
				HAGroup:        "TeamGram-Secondary-HA",
				ClientCertPath: "/etc/hsm/secondary/client.pem",
				ClientKeyPath:  "/etc/hsm/secondary/client.key",
				ServerCertPath: "/etc/hsm/secondary/server.pem",
				HAOnly:         true,
				RecoveryMode:   true,
			},
		},
		// AWS CloudHSM (for cloud deployment)
		{
			Vendor:           hsm.VendorAWSCloudHSM,
			LibraryPath:      "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
			SlotID:           0,
			PIN:              "cloud-hsm-pin",
			Label:            "TeamGram-CloudHSM",
			ConnectTimeout:   30 * time.Second,
			OperationTimeout: 5 * time.Second,
			MaxRetries:       3,
			MaxSessions:      25,
			SessionPoolSize:  12,
			CloudHSMConfig: &hsm.CloudHSMConfig{
				ClusterID:       "cluster-teamgram-prod",
				Region:          "us-east-1",
				AccessKeyID:     "AKIA...",
				SecretAccessKey: "...",
				ENI:             "eni-teamgram-hsm",
				CustomerCA:      "/opt/cloudhsm/etc/customerCA.crt",
			},
		},
	}
}

// GetDevelopmentHSMConfigs returns development-friendly HSM configurations
func GetDevelopmentHSMConfigs() []*hsm.HSMConfig {
	return []*hsm.HSMConfig{
		// SoftHSM for local development
		{
			Vendor:           hsm.VendorSoftHSM,
			LibraryPath:      "/usr/lib/softhsm/libsofthsm2.so",
			SlotID:           0,
			PIN:              "1234",
			Label:            "TeamGram-Dev-SoftHSM",
			ConnectTimeout:   10 * time.Second,
			OperationTimeout: 2 * time.Second,
			MaxRetries:       2,
			MaxSessions:      10,
			SessionPoolSize:  5,
		},
		// Simulator for testing
		{
			Vendor:           hsm.VendorSimulator,
			SlotID:           0,
			PIN:              "simulator-pin",
			Label:            "TeamGram-Dev-Simulator",
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 1 * time.Second,
			MaxRetries:       1,
			MaxSessions:      5,
			SessionPoolSize:  3,
		},
	}
}

// GetHighAvailabilityPoolConfig returns HA pool configuration
func GetHighAvailabilityPoolConfig() *hsm.PoolConfig {
	return &hsm.PoolConfig{
		MaxRetries:          5,
		RetryDelay:          50 * time.Millisecond,
		HealthCheckInterval: 15 * time.Second,
		LoadBalanceStrategy: hsm.HealthBased,
		FailoverEnabled:     true,
		MaxConcurrentOps:    200,
	}
}

// GetPerformanceOptimizedPoolConfig returns performance-optimized pool configuration
func GetPerformanceOptimizedPoolConfig() *hsm.PoolConfig {
	return &hsm.PoolConfig{
		MaxRetries:          2,
		RetryDelay:          25 * time.Millisecond,
		HealthCheckInterval: 60 * time.Second,
		LoadBalanceStrategy: hsm.LeastLoaded,
		FailoverEnabled:     true,
		MaxConcurrentOps:    500,
	}
}
