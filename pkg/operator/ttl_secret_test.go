package operator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
)

type pluginWithRegistrySecret struct {
	vulnerabilityreport.Plugin
}

func (pluginWithRegistrySecret) GetScanJobSpec(_ trivyoperator.PluginContext, _ client.Object, _ map[string]docker.Auth, _ *corev1.SecurityContext, _ map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error) {
	return corev1.PodSpec{}, []*corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "scan-vulnerabilityreport-regcred"}}}, nil
}

func TestTTLSecretReconcilerDeletesExpiredScanJobSecret(t *testing.T) {
	ttl := time.Hour
	_, secrets, err := vulnerabilityreport.NewScanJobBuilder().
		WithPlugin(pluginWithRegistrySecret{}).
		WithPluginContext(trivyoperator.NewPluginContext().
			WithName("trivy").
			WithNamespace("trivy-system").
			WithServiceAccountName("trivy-operator").
			Get()).
		WithTimeout(time.Minute).
		WithScanSecretTTL(&ttl).
		WithObject(&appsv1.ReplicaSet{
			TypeMeta:   metav1.TypeMeta{Kind: "ReplicaSet", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "nginx-6799fc88d8", Namespace: "prod-ns"},
			Spec: appsv1.ReplicaSetSpec{
				Selector: &metav1.LabelSelector{},
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "nginx", Image: "nginx:1.16"}}}},
			},
		}).
		Get()
	require.NoError(t, err)
	require.Len(t, secrets, 1)

	secret := secrets[0]
	require.Equal(t, trivyoperator.AppTrivyOperator, secret.Labels[trivyoperator.LabelK8SAppManagedBy])
	require.Equal(t, ttl.String(), secret.Annotations[v1alpha1.TTLSecretAnnotation])

	clock := ext.NewFixedClock(time.Now())
	secret.CreationTimestamp = metav1.NewTime(clock.Now().Add(-2 * ttl))

	r := &TTLSecretReconciler{
		Logger: log.Log.WithName("testing"),
		Client: fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(secret).Build(),
		Clock:  clock,
	}
	key := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}
	_, err = r.reconcileSecret(&corev1.Secret{})(t.Context(), ctrl.Request{NamespacedName: key})
	require.NoError(t, err)

	err = r.Client.Get(t.Context(), key, &corev1.Secret{})
	require.True(t, apierrors.IsNotFound(err), "expected the expired scan job secret to be deleted, got %v", err)
}
