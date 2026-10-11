package schemaversion

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// Released lineage checksums remain immutable even when the public project
// switches databases. PostgreSQL never adopts these as its current marker.
func TestReleasedMigrationChecksumsRemainImmutable(t *testing.T) {
	for _, test := range []struct {
		checksum func() string
		expected string
	}{
		{LegacyChecksum, "36fda3e649112d6bb44cac424c7a6a7e29a221cc2cc84bde332e8a275fb14985"},
		{EarlierChecksum, "b9faf8e6227a6f73012a1485297fe4fbefdc6b749d0fe266d42f8f8c3c368993"},
		{PreviousChecksum, "2acb3d3ba8e33ac767d8b4289655482f6230264b2295c5e1b2d28aebb1263521"},
		{PermissionPredecessorChecksum, "6ff6e0ddd74bce83772767db256ee36d09bf29f5a55b2edf80e703e25765b8f2"},
		{PermissionChecksum, "9adc31d9aefba95ec2f43fbadde07b2b03541d8e1b61759f75ff79c0b1e41806"},
		{RefreshChecksum, "dbf172edd97106e363bc700a029e8421593bca53e5f9e0df12f9811a7b402d0b"},
		{StepUpChecksum, "8bac5f553a7ffa4c0cab8c306848b7873ee25bc9e8de8e5bb5725debeb49d605"},
		{PermissionRequestChecksum, "43da5840808823ab444aab9cec244bb17dbe186397f71f73060a217bdd8434f4"},
		{TaskAssignmentChecksum, "51cd19f0499d1f1fe00ab289a7956fbfd1f9fb7b0c89c319ac7883cb1c63d901"},
		{OIDCStepUpChecksum, "1e1a2c0fc7b8243c0b4896724bbb4233d8d13cd76a1dfcead837b2f0ba9f5a15"},
		{ConversationBindingChecksum, "ae34005ee86d4b16d24b0b043623ac8ea9f35bb145dd840da3db41e0bbdcf787"},
		{WorkloadBindingChecksum, "e8dab31fadb8d1f340275dc79f7bdf8ade34b7721e43d77ffb3d6693d94cb754"},
		{ErasureChecksum, "404d41fea3e1163f266a9ad6da4816516deae34c5e8b19f7022fcb4ee38c3b9d"},
		{PostgresCheckpointChecksum, "10e36754ba14abddd6ec42e5d80c4a6d3c836a802cc1325f65fc00c8992a77aa"},
		{BusinessStateChecksum, "299e68876c4639b6d6f372b1902f6b57b26770d68ae701cc228df174b2c024fd"},
		{PostgresIndexChecksum, "1b60ff8a6205625c73d49c8a4bd317127447c63b5903e5e6944c5116ce431628"},
		{PostgresSourceChecksum, "fed91126d990900607e89fad770e1f83e04b45f71f31aab962ec3c6967843ac5"},
		{PostgresDirectoryChecksum, "61738659b0d238d8d40a6ee3ccfcc881746b33edcd22d2dca8165e8a7122653c"},
		{PostgresInitialChecksum, "c80c65be2e901b16da3c65ae3cd2c99ec23a47b1ca652afe0bc8fa02c0e0697e"},
		{ModelUsageStepChecksum, "b8400b8b89294da11586e3cc97bed9d3e809120f841a171ffb52c3fc0420e99c"},
		{PermissionCatalogV2Checksum, "437529dc482c967bc8d8e4d6c2c7eb88ed2b50d5b7300580a218b12a21ccad00"},
		{DelegationAuthorityChecksum, "ec84ad0fc98feba0797b9053347922c2aa8510ffb299e0cbdf7f1c76239334f5"},
		{PublicPredecessorChecksum, "cca66ab345c93fce817010b985871c32821ef143b3bdc604b7dfb1311c9572dc"},
	} {
		if got := test.checksum(); got != test.expected {
			t.Fatalf("released checksum changed: %s", got)
		}
	}
}

func TestDelegationAuthorityVersionAndUpgradeMarker(t *testing.T) {
	if !knownPostgresPredecessor(DelegationAuthorityVersion, DelegationAuthorityChecksum()) {
		t.Fatal("released delegation authority migration is not an exact upgrade predecessor")
	}
	if DelegationAuthorityVersion <= PermissionCatalogV2Version || !knownPostgresPredecessor(PermissionCatalogV2Version, PermissionCatalogV2Checksum()) {
		t.Fatal("exact permission catalog v2 marker is not an upgrade predecessor")
	}
	if knownPostgresPredecessor(PermissionCatalogV2Version, "drifted") {
		t.Fatal("permission catalog v2 checksum drift was accepted")
	}
	if knownPostgresPredecessor(DelegationAuthorityVersion+1, DelegationAuthorityChecksum()) {
		t.Fatal("future schema marker was accepted as an upgrade predecessor")
	}
}

func TestCancellationCompensationVersionAppendsReleasedLineage(t *testing.T) {
	if CurrentVersion <= CancellationCompensationVersion || CancellationCompensationVersion <= DelegationAuthorityVersion || !knownPostgresPredecessor(CancellationCompensationVersion, CancellationCompensationChecksum()) {
		t.Fatal("cancellation compensation must append a new immutable native bundle")
	}
	if knownPostgresPredecessor(DelegationAuthorityVersion, "drifted") || knownPostgresPredecessor(CurrentVersion+1, CurrentChecksum()) {
		t.Fatal("drifted or future bundles accepted")
	}
}

func TestLocalCompensationAndNotificationAppendSeparateMigrations(t *testing.T) {
	if CurrentVersion < NotificationReversalVersion || NotificationReversalVersion <= LocalCompensationVersion || !knownPostgresPredecessor(LocalCompensationVersion, LocalCompensationChecksum()) {
		t.Fatal("local before-images and notification receipts must append immutable bundles")
	}
	if knownPostgresPredecessor(LocalCompensationVersion, "drifted") {
		t.Fatal("local effect checksum drift accepted")
	}
}

func TestCancellationEnrollmentPreservesNotificationLineage(t *testing.T) {
	if CurrentVersion <= CancellationEnrollmentVersion || CancellationEnrollmentVersion <= NotificationReversalVersion || !knownPostgresPredecessor(NotificationReversalVersion, NotificationReversalChecksum()) || !knownPostgresPredecessor(CancellationEnrollmentVersion, CancellationEnrollmentChecksum()) {
		t.Fatal("enrollment must append its own migration")
	}
}

func TestCompanyAdministrationAppendsDepartmentRoleCatalog(t *testing.T) {
	departmentChecksum := fmt.Sprintf("%x", sha256.Sum256([]byte(DepartmentAdministrationManifest)))
	if CompanyAdministrationVersion <= DepartmentAdministrationVersion || CurrentVersion < CompanyAdministrationVersion || !knownPostgresPredecessor(DepartmentAdministrationVersion, departmentChecksum) {
		t.Fatal("company authority must append an explicit immutable migration")
	}
	if knownPostgresPredecessor(DepartmentAdministrationVersion, "drifted") || knownPostgresPredecessor(CurrentVersion+1, CurrentChecksum()) {
		t.Fatal("drifted or future administration schema accepted")
	}
}
