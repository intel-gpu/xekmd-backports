#include <linux/vfio_pci_core.h>

struct vfio_pci_vf_token {
	struct mutex		lock;
	uuid_t			uuid;
	int			users;
};

int vfio_pci_core_match_token_uuid(struct vfio_device *core_vdev,
				   const uuid_t *uuid)

{
	struct vfio_pci_core_device *vdev =
		container_of(core_vdev, struct vfio_pci_core_device, vdev);

	/*
	 * There's always some degree of trust or collaboration between SR-IOV
	 * PF and VFs, even if just that the PF hosts the SR-IOV capability and
	 * can disrupt VFs with a reset, but often the PF has more explicit
	 * access to deny service to the VF or access data passed through the
	 * VF.  We therefore require an opt-in via a shared VF token (UUID) to
	 * represent this trust.  This both prevents that a VF driver might
	 * assume the PF driver is a trusted, in-kernel driver, and also that
	 * a PF driver might be replaced with a rogue driver, unknown to in-use
	 * VF drivers.
	 *
	 * Therefore when presented with a VF, if the PF is a vfio device and
	 * it is bound to the vfio-pci driver, the user needs to provide a VF
	 * token to access the device, in the form of appending a vf_token to
	 * the device name, for example:
	 *
	 * "0000:04:10.0 vf_token=bd8d9d2b-5a5f-4f5a-a211-f591514ba1f3"
	 *
	 * When presented with a PF which has VFs in use, the user must also
	 * provide the current VF token to prove collaboration with existing
	 * VF users.  If VFs are not in use, the VF token provided for the PF
	 * device will act to set the VF token.
	 *
	 * If the VF token is provided but unused, an error is generated.
	 */
	if (vdev->pdev->is_virtfn) {
		struct vfio_pci_core_device *pf_vdev = vdev->sriov_pf_core_dev;
		bool match;

		if (!pf_vdev) {
			if (!uuid)
				return 0; /* PF is not vfio-pci, no VF token */

			pci_info_ratelimited(vdev->pdev,
				"VF token incorrectly provided, PF not bound to vfio-pci\n");
			return -EINVAL;
		}

		if (!uuid) {
			pci_info_ratelimited(vdev->pdev,
				"VF token required to access device\n");
			return -EACCES;
		}

		mutex_lock(&pf_vdev->vf_token->lock);
		match = uuid_equal(uuid, &pf_vdev->vf_token->uuid);
		mutex_unlock(&pf_vdev->vf_token->lock);

		if (!match) {
			pci_info_ratelimited(vdev->pdev,
				"Incorrect VF token provided for device\n");
			return -EACCES;
		}
	} else if (vdev->vf_token) {
		mutex_lock(&vdev->vf_token->lock);
		if (vdev->vf_token->users) {
			if (!uuid) {
				mutex_unlock(&vdev->vf_token->lock);
				pci_info_ratelimited(vdev->pdev,
					"VF token required to access device\n");
				return -EACCES;
			}

			if (!uuid_equal(uuid, &vdev->vf_token->uuid)) {
				mutex_unlock(&vdev->vf_token->lock);
				pci_info_ratelimited(vdev->pdev,
					"Incorrect VF token provided for device\n");
				return -EACCES;
			}
		} else if (uuid) {
			uuid_copy(&vdev->vf_token->uuid, uuid);
		}

		mutex_unlock(&vdev->vf_token->lock);
	} else if (uuid) {
		pci_info_ratelimited(vdev->pdev,
			"VF token incorrectly provided, not a PF or VF\n");
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(vfio_pci_core_match_token_uuid);
