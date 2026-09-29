// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { ControlledSelect } from '@nemo/common/src/components/form/ControlledSelect';
import type { UseControllerComponentProps } from '@nemo/common/src/types';
import type { DeploymentMode } from '@studio/components/DeploymentModeSelect/useDeploymentModes';
import type { FC } from 'react';

const DEPLOYMENT_MODE_LABELS: Record<DeploymentMode, string> = {
  subprocess: 'Subprocess',
  docker: 'Docker',
  k8s: 'Kubernetes',
};

interface DeploymentModeSelectProps extends UseControllerComponentProps {
  modes: readonly DeploymentMode[];
  loading?: boolean;
}

export const DeploymentModeSelect: FC<DeploymentModeSelectProps> = ({
  modes,
  loading,
  useControllerProps,
  formFieldProps,
}) => (
  <ControlledSelect
    useControllerProps={useControllerProps}
    loading={loading}
    items={modes.map((mode) => ({ value: mode, children: DEPLOYMENT_MODE_LABELS[mode] }))}
    formFieldProps={{ slotLabel: 'Runtime', ...formFieldProps }}
  />
);
