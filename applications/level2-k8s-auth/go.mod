// No dependencies, deliberately (Stage B D3). The Kubernetes auth handshake is
// implemented by hand with net/http so that it is visible rather than delegated
// to auth.NewKubernetesAuth(). Adding the official Vault SDK here is a failed
// acceptance criterion, checked mechanically in Phase B5.
//
// This comment avoids naming the SDK's import path on purpose: the B5 check is
// a plain grep over this file, and a mention in prose would trip it.
module level2-k8s-auth

go 1.26
