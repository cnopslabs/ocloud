package autonomousdb

import (
	"github.com/cnopslabs/ocloud/internal/domain"
)

// AutonomousDatabase represents an autonomous database instance with its attributes and connection details.
type AutonomousDatabase = domain.AutonomousDatabase

// IndexableAutonomousDatabase represents a simplified autonomous database structure indexed by its name.
type IndexableAutonomousDatabase struct {
	Name string
}
